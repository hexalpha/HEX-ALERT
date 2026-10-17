export async function customRoutesView(root, ui) {
  const {api, esc, heading, table, row, toast, timeMarkup} = ui;
  const [discord, routes] = await Promise.all([api('/api/discord/status'), api('/api/discord/custom-routes')]);
  const guildOptions = discord.guilds.map(g => `<option value="${esc(g.id)}">${esc(g.name)}</option>`).join('');
  root.innerHTML = heading('Channel Routing', 'Manage predefined mappings in Connection and create additional PostgreSQL-backed routes here.') +
    `<section class="section"><h2>Custom Routes</h2><p class="muted">New routes are disabled by default. Test Route explicitly sends one marked message while TEST_MODE is on. A missing mapping never falls back to the test channel.</p>
    <form id="custom-route-form" class="route-form"><div><label>Route name</label><input name="route_name" required maxlength="100" placeholder="AI Security News"></div><div><label>Internal route key</label><input name="route_key" required pattern="[a-z][a-z0-9_]*" maxlength="64" placeholder="ai_security"></div>
    <div class="wide"><label>Description</label><input name="description" maxlength="1000"></div><div><label>Discord server</label><select name="guild_id" required><option value="">Select server</option>${guildOptions}</select></div><div><label>Discord channel</label><select name="channel_id" required disabled><option value="">Select a server first</option></select></div>
    <div><label>Category</label><input name="category" value="custom" maxlength="50" required></div><div><label>Keywords (comma-separated)</label><input name="keywords" placeholder="AI security, prompt injection"></div><div><label>Priority (1 highest–5 lowest)</label><input name="priority" type="number" min="1" max="5" value="3"></div><div><label><input name="enabled" type="checkbox" style="width:auto"> Enabled for automation</label></div>
    <div class="wide row"><button id="route-save" class="primary">Save route disabled</button><button type="button" id="route-cancel" hidden>Cancel edit</button><span id="route-result" class="muted" role="status"></span></div></form></section>
    <section class="section"><h2>Routes · ${routes.length}</h2>${table(['Route Name','Route Key','Mapped Channel','Category / Keywords','Enabled','Last Used','Status','Actions'], routes.map(x => row([
      `<b>${esc(x.route_name)}</b><div class="muted">${esc(x.description)}</div>`, esc(x.route_key), `${esc(x.channel_name ? '#'+x.channel_name : x.channel_id)}<div class="muted">${esc(x.guild_id)} / ${esc(x.channel_id)}</div>`, `${esc(x.category)}<div class="muted">${esc((x.keywords||[]).join(', ') || 'No keywords')}</div>`, x.enabled ? 'Enabled' : 'Disabled', x.last_used ? timeMarkup(x.last_used) : 'Never', esc(x.status),
      `<div class="row"><button data-route-test="${esc(x.route_key)}">Test Route</button><button data-route-edit="${x.id}">Edit</button><button data-route-toggle="${x.id}" data-enable="${!x.enabled}">${x.enabled?'Disable':'Enable'}</button><button class="danger" data-route-delete="${x.id}">Delete</button></div>`
    ])))}</section>
    <section class="section"><h2>Optional: Create Discord Channel</h2><p class="muted">Requires Manage Channels only for this action. Administrator permission is not required or requested.</p><form id="create-channel-form" class="route-form"><div><label>Server</label><select name="guild_id" required><option value="">Select server</option>${guildOptions}</select></div><div><label>Channel name</label><input name="name" required pattern="[a-z0-9_-]+" maxlength="100" placeholder="ai-security"></div><div class="wide"><label>Topic</label><input name="topic" maxlength="1024"></div><div><label>Category / folder</label><select name="category_id"><option value="">No category</option></select></div><div><label>Position (optional)</label><input name="position" type="number" min="0" max="500"></div><div><label><input name="nsfw" type="checkbox" style="width:auto"> NSFW channel</label></div><div class="wide"><button class="primary">Create channel</button> <span id="channel-result" class="muted" role="status"></span></div></form></section>`;

  const form = root.querySelector('#custom-route-form'), guild = form.elements.guild_id, channel = form.elements.channel_id;
  let editingId = null;
  async function loadChannels(guildId, selected='') {
    channel.disabled = true;
    channel.innerHTML = '<option value="">Loading channels…</option>';
    if (!guildId) return;
    try {
      const items = await api(`/api/discord/channels?guild_id=${encodeURIComponent(guildId)}`);
      channel.innerHTML = '<option value="">Select channel</option>' + items.map(c => {
        const ready = c.can_view_channel && c.can_send_messages && c.can_embed_links && c.can_read_message_history;
        return `<option value="${esc(c.id)}" ${ready?'':'disabled'} ${c.id===selected?'selected':''}>#${esc(c.name)}${ready?' · Ready':' · Missing permission'}</option>`;
      }).join('');
      channel.disabled = false;
    } catch (e) { channel.innerHTML = `<option value="">${esc(e.message)}</option>`; }
  }
  guild.onchange = () => loadChannels(guild.value);
  root.querySelector('#route-cancel').onclick = () => customRoutesView(root, ui);
  form.onsubmit = async e => {
    e.preventDefault();
    const fd = new FormData(form), data = Object.fromEntries(fd);
    data.enabled = form.elements.enabled.checked;
    data.priority = Number(data.priority);
    data.keywords = String(data.keywords||'').split(',').map(s=>s.trim()).filter(Boolean);
    const button = root.querySelector('#route-save'); button.disabled = true;
    try {
      await api(editingId ? `/api/discord/custom-routes/${editingId}` : '/api/discord/custom-routes',
        {method: editingId ? 'PUT' : 'POST', body: JSON.stringify(data)});
      toast(editingId ? 'Custom route updated' : 'Custom route saved');
      await customRoutesView(root, ui);
    } catch (err) { root.querySelector('#route-result').textContent = err.message; button.disabled = false; }
  };
  root.querySelectorAll('[data-route-test]').forEach(button => button.onclick = async () => {
    button.disabled = true;
    try {
      const d = await api(`/api/discord/custom-routes/${encodeURIComponent(button.dataset.routeTest)}/test`, {method:'POST'});
      toast(`CUSTOM ROUTE TEST sent to #${d.channel_name}; message ${d.message_id} stored`);
      await customRoutesView(root, ui);
    } catch (err) { toast(err.message); button.disabled = false; }
  });
  root.querySelectorAll('[data-route-edit]').forEach(button => button.onclick = async () => {
    const item = routes.find(r => r.id === Number(button.dataset.routeEdit)); if (!item) return;
    editingId = item.id;
    for (const key of ['route_name','route_key','description','guild_id','category','priority']) form.elements[key].value = item[key] ?? '';
    form.elements.keywords.value = (item.keywords||[]).join(', '); form.elements.enabled.checked = item.enabled;
    guild.value = item.guild_id; await loadChannels(item.guild_id, item.channel_id);
    root.querySelector('#route-save').textContent = 'Update route'; root.querySelector('#route-cancel').hidden = false;
    form.scrollIntoView({behavior:'smooth',block:'start'});
  });
  root.querySelectorAll('[data-route-toggle]').forEach(button => button.onclick = async () => {
    const item = routes.find(r => r.id === Number(button.dataset.routeToggle)); if (!item) return;
    const data = {route_name:item.route_name,route_key:item.route_key,description:item.description,guild_id:item.guild_id,
      channel_id:item.channel_id,category:item.category,keywords:item.keywords||[],priority:item.priority,
      enabled:button.dataset.enable==='true'};
    try { await api(`/api/discord/custom-routes/${item.id}`,{method:'PUT',body:JSON.stringify(data)}); await customRoutesView(root,ui); }
    catch(err) { toast(err.message); }
  });
  root.querySelectorAll('[data-route-delete]').forEach(button => button.onclick = async () => {
    if (!confirm('Delete this custom route? Rules using it will fail safely until updated.')) return;
    try { await api(`/api/discord/custom-routes/${button.dataset.routeDelete}`,{method:'DELETE'}); await customRoutesView(root,ui); }
    catch(err) { toast(err.message); }
  });

  const create = root.querySelector('#create-channel-form'), createGuild = create.elements.guild_id, categories = create.elements.category_id;
  createGuild.onchange = async () => {
    categories.innerHTML = '<option value="">Loading…</option>';
    try { const list = await api(`/api/discord/categories?guild_id=${encodeURIComponent(createGuild.value)}`);
      categories.innerHTML = '<option value="">No category</option>' + list.map(c=>`<option value="${esc(c.id)}">${esc(c.name)}</option>`).join('');
    } catch (err) { categories.innerHTML = `<option value="">${esc(err.message)}</option>`; }
  };
  create.onsubmit = async e => {
    e.preventDefault(); const data = Object.fromEntries(new FormData(create));
    data.nsfw = create.elements.nsfw.checked; data.position = data.position ? Number(data.position) : null;
    try { const d = await api('/api/discord/create-channel',{method:'POST',body:JSON.stringify(data)});
      root.querySelector('#channel-result').textContent = `Created #${d.name} (${d.id}).`;
      if (guild.value === d.guild_id) await loadChannels(guild.value,d.id);
    } catch (err) { root.querySelector('#channel-result').textContent = err.message; }
  };
}
