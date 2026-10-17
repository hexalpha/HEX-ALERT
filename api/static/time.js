(() => {
  let settings = { timezone: 'Asia/Kolkata', time_format: '12h', timezone_abbr: 'IST' };
  const MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const parse = value => {
    if (value == null || value === '') return null;
    if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
    const raw = String(value).trim();
    if (/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
      const [y,m,d] = raw.split('-').map(Number);
      return { dateOnly: true, y, m, d };
    }
    // API-naive timestamps are legacy UTC values, never browser-local values.
    const normalized = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(raw) ? raw : `${raw}Z`;
    const date = new Date(normalized);
    return Number.isNaN(date.getTime()) ? null : date;
  };
  function parts(value, options) {
    return Object.fromEntries(new Intl.DateTimeFormat('en-GB', { timeZone: settings.timezone, ...options }).formatToParts(value).map(x => [x.type, x.value]));
  }
  function formatDateTime(value) {
    const date = parse(value);
    if (!date) return 'Not available';
    if (date.dateOnly) return `${String(date.d).padStart(2,'0')} ${MONTHS[date.m-1]} ${date.y}`;
    const p = parts(date, { day:'2-digit', month:'short', year:'numeric', hour: settings.time_format === '24h' ? '2-digit' : 'numeric', minute:'2-digit', ...(settings.time_format === '24h' ? {hourCycle:'h23'} : {hour12:true}), timeZoneName:'short' });
    const time = settings.time_format === '24h' ? `${p.hour}:${p.minute}` : `${p.hour}:${p.minute} ${String(p.dayPeriod||'').toUpperCase()}`;
    const zone = settings.timezone === 'Asia/Kolkata' ? 'IST' : ['UTC','Etc/UTC'].includes(settings.timezone) ? 'UTC' : (p.timeZoneName||settings.timezone_abbr);
    return `${p.day} ${p.month} ${p.year}, ${time} ${zone}`;
  }
  function formatDate(value) {
    const date = parse(value);
    if (!date) return 'Not available';
    if (date.dateOnly) return `${String(date.d).padStart(2,'0')} ${MONTHS[date.m-1]} ${date.y}`;
    const p = parts(date, { day:'2-digit', month:'short', year:'numeric' });
    return `${p.day} ${p.month} ${p.year}`;
  }
  function formatTime(value) {
    const date = parse(value);
    if (!date || date.dateOnly) return 'Not available';
    const p = parts(date, { hour: settings.time_format === '24h' ? '2-digit' : 'numeric', minute:'2-digit', ...(settings.time_format === '24h' ? {hourCycle:'h23'} : {hour12:true}), timeZoneName:'short' });
    const zone = settings.timezone === 'Asia/Kolkata' ? 'IST' : ['UTC','Etc/UTC'].includes(settings.timezone) ? 'UTC' : (p.timeZoneName||settings.timezone_abbr);
    return settings.time_format === '24h' ? `${p.hour}:${p.minute} ${zone}` : `${p.hour}:${p.minute} ${String(p.dayPeriod||'').toUpperCase()} ${zone}`;
  }
  function formatRelativeTime(value, now = new Date()) {
    const date = parse(value);
    if (!date || date.dateOnly) return formatDateTime(value);
    const seconds = (date.getTime() - now.getTime()) / 1000;
    const units = [['year',31536000],['month',2592000],['week',604800],['day',86400],['hour',3600],['minute',60],['second',1]];
    const [unit,size] = units.find(([,size]) => Math.abs(seconds) >= size) || units[units.length-1];
    return new Intl.RelativeTimeFormat('en', { numeric:'auto' }).format(Math.round(seconds/size), unit);
  }
  const toISO = value => { const date=parse(value); return date && !date.dateOnly ? date.toISOString() : ''; };
  window.HexAlertTime = {
    configure(value={}) { settings = { ...settings, ...value }; if (!settings.timezone) settings.timezone='Asia/Kolkata'; if (!['12h','24h'].includes(settings.time_format)) settings.time_format='12h'; },
    get settings() { return { ...settings }; }, parse, toISO, formatDateTime, formatDate, formatTime, formatRelativeTime,
  };
})();
