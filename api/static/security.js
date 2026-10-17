export async function securityView(root, ui) {
  const {api, esc, heading, toast, showLogin, formatDateTime} = ui;
  const [s, accountData] = await Promise.all([api('/api/security/admin-status'), api('/api/auth/accounts')]);
  const accounts = accountData.accounts || [];
  const current = accounts.find(x => x.current);
  const yes = value => value ? 'Yes' : 'No';
  root.innerHTML = heading('Security','Administrator accounts, PIN sign-in, password, and recovery controls') +
    `<div class="grid"><div class="card"><div class="muted">Signed in as</div><b>${esc(current?.username || 'Admin')}</b></div><div class="card"><div class="muted">Administrator accounts</div><b>${accounts.length}</b></div><div class="card"><div class="muted">MFA enabled</div><b>${yes(s.mfa_enabled)}</b></div><div class="card"><div class="muted">Last successful login</div><b>${s.last_successful_login?formatDateTime(s.last_successful_login):'Not recorded'}</b></div><div class="card"><div class="muted">Failed login attempts</div><b>${esc(s.failed_login_attempts)}</b></div><div class="card"><div class="muted">Session count</div><b>${esc(s.session_count)}</b></div><div class="card"><div class="muted">Password last changed</div><b>${s.password_changed_at?formatDateTime(s.password_changed_at):'Not recorded'}</b></div></div>
    <section class="section"><h2>Administrator accounts</h2><p class="muted">Each account has full dashboard administrator access. Use Switch user to change accounts without closing the dashboard.</p><div class="item">${accounts.map(a=>`<span class="tag">${esc(a.username)}${a.current?' · current':''}${a.pin_configured?' · PIN set':''}</span>`).join(' ')}</div><form id="create-admin-account" class="formgrid"><div><label>New username</label><input name="username" minlength="3" maxlength="80" pattern="[A-Za-z0-9_.-]+" required autocomplete="off"></div><div><label>New password (at least 12 characters)</label><input name="password" type="password" minlength="12" maxlength="256" required autocomplete="new-password"></div><div><label>Optional 6-digit PIN</label><input name="pin" type="password" inputmode="numeric" pattern="[0-9]{6}" minlength="6" maxlength="6" autocomplete="off"></div><div class="wide"><button class="primary">Add administrator account</button> <span id="account-result" class="muted" role="status"></span></div></form></section>
    <section class="section"><h2>6-digit PIN sign-in</h2><p class="muted">PIN is optional and stored as a salted password hash. Use a unique PIN; sign-in attempts are rate limited. Your password remains available.</p><p>PIN configured: <b>${yes(current?.pin_configured)}</b></p><form id="pin-settings" class="formgrid"><div><label>Current password</label><input name="current_password" type="password" minlength="12" maxlength="256" required autocomplete="current-password"></div><div><label>New 6-digit PIN</label><input name="pin" type="password" inputmode="numeric" pattern="[0-9]{6}" minlength="6" maxlength="6" autocomplete="new-password" placeholder="Six digits"></div>${s.mfa_enabled?'<div class="wide"><label>Current authenticator code</label><input name="code" maxlength="6" inputmode="numeric" autocomplete="one-time-code" required></div>':''}<div class="wide"><button class="primary">Save PIN</button> <button type="button" id="clear-pin">Clear PIN</button> <span id="pin-result" class="muted" role="status"></span></div></form></section>
    <section class="section"><h2>Change password</h2><form id="change-password" class="formgrid"><div><label>Current password</label><input name="current_password" type="password" minlength="12" required autocomplete="current-password"></div><div><label>New password (at least 12 characters)</label><input name="new_password" type="password" minlength="12" required autocomplete="new-password"></div>${s.mfa_enabled?'<div class="wide"><label>Current authenticator code</label><input name="code" maxlength="6" inputmode="numeric" autocomplete="one-time-code" required></div>':''}<div class="wide"><button class="primary">Change password</button> <span id="password-result" class="muted" role="status"></span></div></form></section>
    <section class="section"><h2>Change password</h2><form id="change-password" class="formgrid"><div><label>Current password</label><input name="current_password" type="password" minlength="12" required autocomplete="current-password"></div><div><label>New password (at least 12 characters)</label><input name="new_password" type="password" minlength="12" required autocomplete="new-password"></div>${s.mfa_enabled?'<div class="wide"><label>Current authenticator code</label><input name="code" maxlength="6" inputmode="numeric" autocomplete="one-time-code" required></div>':''}<div class="wide"><button class="primary">Change password</button> <span id="password-result" class="muted" role="status"></span></div></form></section>
    <section class="section"><h2>Recovery codes</h2><p class="muted">New codes replace all existing codes. They are stored as hashes and shown only once.</p>${s.mfa_enabled?'<form id="regen-codes"><label>Current password</label><input name="password" type="password" minlength="12" required autocomplete="current-password"><label>Current authenticator code</label><input name="code" maxlength="6" inputmode="numeric" required autocomplete="one-time-code"><p><button class="primary">Generate new recovery codes</button></p></form>':'<p>MFA is disabled. Enable it in Settings before generating recovery codes.</p>'}<div id="recovery-output" aria-live="polite"></div></section>
    <section class="section"><h2>Forgot password</h2><p>Recovery needs trusted local access to the HEX ALERT machine. From the project folder run <code>docker compose exec bot python manage.py admin-reset</code>, then enter the one-time token from that local terminal on the sign-in page. It expires after 15 minutes.</p></section>`;
  root.querySelector('#create-admin-account').onsubmit = async e => {
    e.preventDefault(); const result=root.querySelector('#account-result'), data=Object.fromEntries(new FormData(e.target));
    data.username=data.username.trim(); if(!data.pin)data.pin=null;
    try { await api('/api/auth/accounts',{method:'POST',body:JSON.stringify(data)}); result.textContent='Account added. It can now sign in from this browser.';
      try { const saved=JSON.parse(localStorage.getItem('hexalert-admin-accounts')||'[]'); if(!saved.some(x=>x.toLowerCase()===data.username.toLowerCase()))saved.push(data.username); localStorage.setItem('hexalert-admin-accounts',JSON.stringify(saved.slice(-10))); } catch {}
      e.target.reset(); toast('Administrator account added'); setTimeout(()=>securityView(root,ui),300);
    } catch(err) { result.textContent=err.message; }
  };
  const sendPinUpdate = async (clear=false) => {
    const form=root.querySelector('#pin-settings'),result=root.querySelector('#pin-result'),data=Object.fromEntries(new FormData(form));
    if(!clear&&!/^\d{6}$/.test(data.pin||'')){result.textContent='Enter exactly six digits.';return}
    data.clear=clear; if(clear)delete data.pin;
    try { await api('/api/auth/pin',{method:'POST',body:JSON.stringify(data)}); result.textContent=clear?'PIN cleared. Password sign-in remains available.':'PIN saved. You can now sign in with either PIN or password.'; form.reset(); toast(clear?'PIN cleared':'PIN saved'); }
    catch(err) { result.textContent=err.message; }
  };
  root.querySelector('#pin-settings').onsubmit=e=>{e.preventDefault();sendPinUpdate(false)};
  root.querySelector('#clear-pin').onclick=()=>{if(confirm('Clear PIN sign-in for this account? Password sign-in will remain available.'))sendPinUpdate(true)};
  root.querySelector('#change-password').onsubmit = async e => {
    e.preventDefault(); const result=root.querySelector('#password-result');
    try { await api('/api/auth/change-password',{method:'POST',body:JSON.stringify(Object.fromEntries(new FormData(e.target)))});
      result.textContent='Password changed. All existing sessions were invalidated; sign in again.';
      setTimeout(()=>showLogin(),900);
    } catch(err) { result.textContent=err.message; }
  };
  root.querySelector('#regen-codes')?.addEventListener('submit', async e => {
    e.preventDefault();
    try { const d=await api('/api/mfa/recovery-codes',{method:'POST',body:JSON.stringify(Object.fromEntries(new FormData(e.target)))});
      root.querySelector('#recovery-output').innerHTML=`<h3>Save these codes now</h3><pre>${esc(d.recovery_codes.join('\n'))}</pre><p class="muted">They will not be shown again.</p>`;
    } catch(err) { toast(err.message); }
  });
}
