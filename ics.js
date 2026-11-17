/**
 * Minimal iCalendar (RFC 5545) reader for importing the compliance .ics files: VEVENTs with
 * UID, SUMMARY, DESCRIPTION, DTSTART/DTEND (all-day or timed), RRULE/RDATE/EXDATE, and VALARM
 * triggers. Anything it cannot represent is reported per event, never silently dropped.
 */

const MAX_ICS_BYTES = 2 * 1024 * 1024;
const MAX_EVENTS = 1000;

function unescapeText(value) {
  return value.replace(/\\([\\;,nN])/g, (_, c) => (c === 'n' || c === 'N' ? '\n' : c));
}

/** Split `NAME;P=V;P2="a:b":value` at the first colon outside a quoted parameter. */
function splitLine(line) {
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    if (line[i] === '"') quoted = !quoted;
    else if (line[i] === ':' && !quoted) {
      const [name, ...params] = line.slice(0, i).split(';');
      const map = {};
      for (const p of params) {
        const eq = p.indexOf('=');
        if (eq > 0) map[p.slice(0, eq).toUpperCase()] = p.slice(eq + 1).replace(/^"|"$/g, '');
      }
      return { name: name.toUpperCase(), params: map, value: line.slice(i + 1) };
    }
  }
  return null;
}

/** "-P7D" → 10080 minutes before; positive triggers (after the start) return a negative number. */
export function triggerMinutes(value) {
  const m = /^([+-])?P(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/.exec(value);
  if (!m || value === 'P' || value.endsWith('T')) return null;
  const [, sign, w, d, h, min, sec] = m;
  const total =
    Number(w || 0) * 10080 +
    Number(d || 0) * 1440 +
    Number(h || 0) * 60 +
    Number(min || 0) +
    Math.floor(Number(sec || 0) / 60);
  return sign === '-' ? total : -total;
}

function parseDate(prop) {
  const v = prop.value;
  if (prop.params.VALUE === 'DATE' || /^\d{8}$/.test(v)) {
    if (!/^\d{8}$/.test(v)) return null;
    return { date: `${v.slice(0, 4)}-${v.slice(4, 6)}-${v.slice(6, 8)}` };
  }
  const m = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})(Z?)$/.exec(v);
  if (!m) return null;
  const local = `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}`;
  if (m[7]) return { dateTime: `${local}Z` };
  return { dateTime: local, timeZone: prop.params.TZID };
}

/**
 * @param {string} text
 * @returns {{ events: any[], warnings: string[] }}
 */
export function parseIcs(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > MAX_ICS_BYTES)
    throw new Error('Calendar file missing or larger than 2 MB');
  const lines = text
    .replace(/\r\n?/g, '\n')
    .replace(/\n[ \t]/g, '')
    .split('\n')
    .filter((l) => l.trim());
  const events = [];
  const warnings = [];
  /** @type {any} */
  let event = null;
  /** @type {any} */
  let alarm = null;
  const stack = [];
  for (const raw of lines) {
    const prop = splitLine(raw);
    if (!prop) continue;
    if (prop.name === 'BEGIN') {
      stack.push(prop.value.toUpperCase());
      if (prop.value.toUpperCase() === 'VEVENT') {
        if (events.length >= MAX_EVENTS) throw new Error('Calendar file has too many events');
        event = /** @type {any} */ ({ recurrence: [], alarms: [], problems: [] });
      } else if (prop.value.toUpperCase() === 'VALARM' && event) alarm = {};
      continue;
    }
    if (prop.name === 'END') {
      const kind = stack.pop();
      if (kind === 'VALARM' && event && alarm) {
        const minutes = alarm.trigger === undefined ? null : triggerMinutes(alarm.trigger);
        if (alarm.related === 'END')
          event.problems.push(`alarm relative to end (${alarm.trigger})`);
        else if (minutes === null) event.problems.push(`unreadable alarm "${alarm.trigger}"`);
        else event.alarms.push({ minutes, trigger: alarm.trigger });
        alarm = null;
      } else if (kind === 'VEVENT' && event) {
        if (!event.uid || !event.start) warnings.push('Skipped a VEVENT without UID or DTSTART');
        else events.push(event);
        event = null;
      }
      continue;
    }
    if (!event) continue;
    if (alarm) {
      if (prop.name === 'TRIGGER') {
        alarm.trigger = prop.value;
        alarm.related = prop.params.RELATED;
        if (prop.params.VALUE === 'DATE-TIME') alarm.trigger = `absolute:${prop.value}`;
      }
      continue;
    }
    switch (prop.name) {
      case 'UID':
        event.uid = prop.value;
        break;
      case 'SUMMARY':
        event.summary = unescapeText(prop.value);
        break;
      case 'DESCRIPTION':
        event.description = unescapeText(prop.value);
        break;
      case 'DTSTART':
        event.start = parseDate(prop);
        if (!event.start) event.problems.push(`unreadable DTSTART "${prop.value}"`);
        break;
      case 'DTEND':
        event.end = parseDate(prop);
        break;
      case 'RRULE':
      case 'RDATE':
      case 'EXDATE':
        event.recurrence.push(`${raw.split(':')[0]}:${prop.value}`);
        break;
      case 'ATTENDEE':
      case 'ORGANIZER':
        event.problems.push(`${prop.name} ignored (deadlines never have guests)`);
        break;
      default:
        break;
    }
  }
  return { events, warnings };
}
