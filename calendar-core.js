/**
 * Google Calendar access, per account, limited to the calendars listed in accounts.json.
 *
 * Each account's `calendars` maps a name of your choosing to a calendar this app creates
 * (`create`), an existing calendar (`id`, e.g. "primary"), or `*` (any calendar the account can
 * see), each with `access` read or write. The OAuth scope is derived from that list: created
 * calendars only → calendar.app.created, where Google itself confines the app; existing calendars
 * → calendar.events(.readonly), where this module enforces the list before every request.
 *
 * Rules on every calendar: no guests are ever added, every change sends no notifications, and
 * events that have guests (real meetings) or are special Google types are read-only here.
 *
 * Calendars with `kind: "deadlines"` follow the compliance format shared with the hub and the
 * Proton .ics files: UIDs are obligation ids (existing kept; new <entity>-<slug>@compliance),
 * titles start with "<ENTITY>: ", descriptions end with "Body: CA-FTB · Entity: acme" (Body
 * optional), recurrence stays as RRULEs, default reminders 28 and 7 days, events marked free.
 *
 * The MCP server (index.js) and other local tools (the compliance hub) call these operations.
 */

import { CALENDAR_ROOT, googleJson, USERINFO_URL } from './google-http.js';
import { createTokenManager } from './oauth.js';
import { withOperationSlot } from './runtime.js';
import { isCalendarDate } from './security.js';

export const CAL_SERVICE = 'multi-mail-mcp.gcal-oauth';
const G = 'https://www.googleapis.com/auth/';
export const SCOPES = {
  email: `${G}userinfo.email`,
  appCreated: `${G}calendar.app.created`,
  events: `${G}calendar.events`,
  eventsRead: `${G}calendar.events.readonly`,
  calendarList: `${G}calendar.calendarlist.readonly`,
};
export const TIME_ZONE = 'America/Los_Angeles';
export const DEFAULT_REMINDERS = ['28d', '7d'];
const MAX_REMINDER_MINUTES = 40320; // Google's limit: four weeks.
const CREATED_ID_RE = /^[a-z0-9]{1,128}@group\.calendar\.google\.com$/;
const ANY_ID_RE = /^(?:primary|[A-Za-z0-9._#+-]{1,200}@[A-Za-z0-9.-]{1,100})$/;
const EVENT_ID_RE = /^[A-Za-z0-9_-]{1,1024}$/;
const UID_RE = /^[A-Za-z0-9][A-Za-z0-9@._-]{0,254}$/;
const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const BODY_RE = /^[A-Z][A-Z0-9-]{0,15}$/;
const RRULE_RE = /^FREQ=(?:YEARLY|MONTHLY|WEEKLY|DAILY)(?:;[A-Z]+=[A-Z0-9,+-]+){0,8}$/;
const META_RE = /(?:^|\n)(?:Body: ([A-Z][A-Z0-9-]{0,15}) · )?Entity: ([a-z][a-z0-9]{0,15})\s*$/;
// biome-ignore lint/suspicious/noControlCharactersInRegex: Reject control characters in event text.
const CONTROL = /[\x00-\x08\x0b-\x1f\x7f]/;

/** @param {import('./types.js').Account} account */
export const entityOf = (account) => account.entity || account.id;
const configured = (account) => Object.entries(account.calendars || {});

/** The exact scope set an account's configured calendars need. */
export function scopesFor(account) {
  const cals = configured(account);
  if (!cals.length) throw new Error(`No calendars configured for "${account.id}" in accounts.json`);
  const scopes = ['openid', SCOPES.email];
  if (cals.some(([, c]) => c.create)) scopes.push(SCOPES.appCreated);
  const existing = cals.filter(([k, c]) => k === '*' || c.id);
  if (existing.some(([, c]) => c.access === 'write')) scopes.push(SCOPES.events);
  else if (existing.length) scopes.push(SCOPES.eventsRead);
  if (account.calendars['*']) scopes.push(SCOPES.calendarList);
  return scopes;
}

function headers(accessToken, json = false) {
  return {
    Authorization: `Bearer ${accessToken}`,
    ...(json ? { 'Content-Type': 'application/json' } : {}),
  };
}

/**
 * OAuth profile for one account: its scopes follow its configured calendars, so changing
 * the calendars in accounts.json to need more access requires running auth again.
 * @param {import('./types.js').Account} account
 * @returns {import('./oauth.js').OAuthProfile}
 */
export function calendarProfile(account) {
  const scopes = scopesFor(account);
  return {
    name: 'Google Calendar',
    service: CAL_SERVICE,
    scopes,
    requestScope: scopes.map((s) => (s === SCOPES.email ? 'email' : s)).join(' '),
    scopeError: `Calendar grant does not match the calendars configured for "${account.id}" in accounts.json; run auth --calendar again`,
    command: 'CAL_ACCOUNTS=%s node index.js auth %s --calendar',
    metadata: ['calendar_ids'],
    async identity(accessToken, fetchImpl, signal) {
      const info = await googleJson(
        USERINFO_URL,
        { headers: headers(accessToken), signal },
        { fetchImpl, maxBytes: 65536 },
      );
      if (info.email_verified !== true) throw new Error('Google account email is not verified');
      return info.email;
    },
    /** Create `create` calendars (or reuse them from a previous login); check `id` calendars. */
    async prepare(accessToken, fetchImpl, previous) {
      const ids = {};
      const report = [];
      for (const [key, c] of configured(account)) {
        if (key === '*') continue;
        if (c.id) {
          await googleJson(
            `${CALENDAR_ROOT}calendars/${encodeURIComponent(c.id)}/events?maxResults=1`,
            { headers: headers(accessToken) },
            { fetchImpl },
          );
          report.push(`${key}: existing calendar ${c.id} (${c.access})`);
          continue;
        }
        const known = previous?.calendar_ids?.[key];
        if (typeof known === 'string' && CREATED_ID_RE.test(known)) {
          try {
            await googleJson(
              `${CALENDAR_ROOT}calendars/${encodeURIComponent(known)}`,
              { headers: headers(accessToken) },
              { fetchImpl },
            );
            ids[key] = known;
            report.push(`${key}: "${c.create}" (kept, ${c.access})`);
            continue;
          } catch (err) {
            if (err.status !== 403 && err.status !== 404) throw err;
          }
        }
        const cal = await googleJson(
          `${CALENDAR_ROOT}calendars`,
          {
            method: 'POST',
            headers: headers(accessToken, true),
            body: JSON.stringify({ summary: c.create, timeZone: TIME_ZONE }),
          },
          { fetchImpl },
        );
        if (typeof cal.id !== 'string' || !CREATED_ID_RE.test(cal.id))
          throw new Error('Google returned an unexpected calendar id');
        ids[key] = cal.id;
        report.push(`${key}: "${c.create}" (created, ${c.access})`);
      }
      return { calendar_ids: ids, calendars: report };
    },
  };
}

export const calendarTokens = createTokenManager({ profile: calendarProfile });

// --- Validation (other local tools call these operations directly, not only through MCP) -----

function text(value, name, max, { multiline = false } = {}) {
  if (typeof value !== 'string' || value.length > max || (!multiline && /[\r\n]/.test(value)))
    throw new Error(`${name} must be text of at most ${max} characters`);
  if (CONTROL.test(value)) throw new Error(`${name} contains control characters`);
  return value;
}

function checkUid(uid) {
  if (typeof uid !== 'string' || !UID_RE.test(uid)) throw new Error('Invalid event uid');
  return uid;
}

/** "28d", "7d", "2h", "30m" → minutes before the event. */
export function reminderMinutes(spec) {
  const m = typeof spec === 'string' ? /^(\d{1,5})([dhm])$/.exec(spec) : null;
  const minutes = m ? Number(m[1]) * { d: 1440, h: 60, m: 1 }[m[2]] : Number.NaN;
  if (!(minutes >= 0 && minutes <= MAX_REMINDER_MINUTES))
    throw new Error(
      `Reminder "${String(spec).slice(0, 20)}" must look like 28d, 2h or 30m (max 28d)`,
    );
  return minutes;
}

const formatMinutes = (n) =>
  n % 1440 === 0 && n ? `${n / 1440}d` : n % 60 === 0 && n ? `${n / 60}h` : `${n}m`;

function reminders(specs) {
  if (!Array.isArray(specs) || specs.length > 5) throw new Error('At most 5 reminders');
  const minutes = [...new Set(specs.map(reminderMinutes))];
  return { useDefault: false, overrides: minutes.map((n) => ({ method: 'popup', minutes: n })) };
}

function recurrence(rule) {
  if (rule === null || rule === '') return [];
  const r = String(rule).replace(/^RRULE:/, '');
  if (!RRULE_RE.test(r)) throw new Error('recurrence must be an RRULE such as FREQ=YEARLY');
  return [`RRULE:${r}`];
}

// --- Time zone arithmetic without a dependency ---------------------------------

function zoneOffsetMs(utcMs, tz) {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: tz,
    hourCycle: 'h23',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).formatToParts(new Date(utcMs));
  const get = (t) => Number(parts.find((p) => p.type === t)?.value);
  return (
    Date.UTC(get('year'), get('month') - 1, get('day'), get('hour'), get('minute'), get('second')) -
    utcMs
  );
}

/** Wall-clock date (and time) in `tz` → RFC 3339 UTC instant. */
export function zonedToUtc(date, time = '00:00:00', tz = TIME_ZONE) {
  const naive = Date.parse(`${date}T${time}Z`);
  const first = naive - zoneOffsetMs(naive, tz);
  return new Date(naive - zoneOffsetMs(first, tz)).toISOString();
}

export function todayIn(tz = TIME_ZONE) {
  return new Intl.DateTimeFormat('en-CA', { timeZone: tz }).format(new Date());
}

export function addDays(date, days) {
  return new Date(Date.parse(`${date}T00:00:00Z`) + days * 86400000).toISOString().slice(0, 10);
}

function addMinutesLocal(dateTime, minutes) {
  return new Date(Date.parse(`${dateTime}Z`) + minutes * 60000).toISOString().slice(0, 19);
}

// --- Event shape -----------------------------------------------------------------

export function parseMeta(description = '') {
  const plain = String(description).replace(/<br\s*\/?>/gi, '\n');
  const m = META_RE.exec(plain);
  if (!m) return { notes: plain.trim(), body: null, entity: null };
  return { notes: plain.slice(0, m.index).trim(), body: m[1] || null, entity: m[2] };
}

export function composeDescription(notes, body, entity) {
  const meta = `${body ? `Body: ${body} · ` : ''}Entity: ${entity}`;
  return [String(notes || '').trim(), meta].filter(Boolean).join('\n\n');
}

function title(value, entity) {
  const t = text(value, 'title', 300).trim();
  if (!t) throw new Error('title is required');
  if (!entity) return t;
  const prefix = `${entity.toUpperCase()}:`;
  return t.startsWith(prefix) ? t : `${prefix} ${t}`;
}

const DATE_TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/;
function checkDateTime(value, name) {
  if (
    typeof value !== 'string' ||
    !DATE_TIME_RE.test(value) ||
    !isCalendarDate(value.slice(0, 10)) ||
    Number(value.slice(11, 13)) > 23 ||
    Number(value.slice(14, 16)) > 59
  )
    throw new Error(`${name} must be YYYY-MM-DDTHH:MM in ${TIME_ZONE}`);
  return `${value}:00`;
}

/**
 * Start/end: all-day `date` (with optional inclusive `end_date`) or timed `date_time`
 * (with optional `end_date_time`, default 30 minutes later for deadlines, 60 otherwise).
 * @param {{ date?: string, end_date?: string, date_time?: string, end_date_time?: string }} input
 */
function when({ date, end_date, date_time, end_date_time }, defaultMinutes = 60) {
  if (date !== undefined && date_time !== undefined)
    throw new Error('Give either date (all-day) or date_time, not both');
  if (date !== undefined) {
    if (typeof date !== 'string' || !isCalendarDate(date))
      throw new Error('date must be YYYY-MM-DD');
    if (end_date !== undefined && (!isCalendarDate(end_date) || end_date < date))
      throw new Error('end_date must be YYYY-MM-DD, on or after date');
    return { start: { date }, end: { date: addDays(end_date ?? date, 1) } };
  }
  const start = checkDateTime(date_time, 'date_time');
  const end =
    end_date_time === undefined
      ? addMinutesLocal(start, defaultMinutes)
      : checkDateTime(end_date_time, 'end_date_time');
  if (end <= start) throw new Error('end_date_time must be after date_time');
  return {
    start: { dateTime: start, timeZone: TIME_ZONE },
    end: { dateTime: end, timeZone: TIME_ZONE },
  };
}

const privateProps = (uid, entity, body) => ({
  private: { obligation_id: uid, entity, ...(body ? { body } : {}), managed_by: 'multi-mail-mcp' },
});

/** Normalized event, as the MCP tools and other local tools see it. */
export function normalize(e, calendar, kind) {
  const allDay = Boolean(e.start?.date);
  const description = typeof e.description === 'string' ? e.description : '';
  const rec = Array.isArray(e.recurrence) ? e.recurrence.map(String) : [];
  const guests = Array.isArray(e.attendees) ? e.attendees.length : 0;
  const base = {
    calendar,
    uid: e.iCalUID,
    summary: typeof e.summary === 'string' ? e.summary : '',
    all_day: allDay,
    dtstart: allDay ? e.start.date : e.start?.dateTime || null,
    dtend: allDay ? e.end?.date || null : e.end?.dateTime || null,
    rrule: rec.find((r) => r.startsWith('RRULE:'))?.slice(6) || null,
    recurrence: rec,
    ...(e.recurringEventId
      ? { occurrence: e.originalStartTime?.date || e.originalStartTime?.dateTime || null }
      : {}),
    ...(typeof e.location === 'string' && e.location ? { location: e.location } : {}),
    description,
    reminders: Array.isArray(e.reminders?.overrides)
      ? e.reminders.overrides.map((r) => formatMinutes(Number(r.minutes)))
      : [],
    ...(guests ? { guests, organizer: String(e.organizer?.email || '') } : {}),
    ...(guests || (e.eventType && e.eventType !== 'default') ? { read_only: true } : {}),
    source: 'google',
  };
  if (kind !== 'deadlines') return base;
  const meta = parseMeta(description);
  const priv = e.extendedProperties?.private || {};
  return {
    ...base,
    entity: meta.entity || priv.entity || null,
    body: meta.body || priv.body || null,
    notes: meta.notes,
  };
}

// --- Client ------------------------------------------------------------------------

/**
 * @param {import('./types.js').Account} account
 * @param {{ tokens?: ReturnType<typeof createTokenManager>, fetchImpl?: typeof fetch, signal?: AbortSignal, maxRequests?: number }} [options]
 */
export function createCalendarClient(
  account,
  { tokens = calendarTokens, fetchImpl = fetch, signal, maxRequests = 100 } = {},
) {
  let requests = 0;
  /**
   * @param {'GET'|'POST'|'PATCH'|'DELETE'} method
   * @param {string} path Under CALENDAR_ROOT; already resolved against the account's calendars.
   * @param {{ params?: Record<string, unknown>, body?: unknown }} [options]
   */
  async function request(method, path, { params = {}, body } = {}) {
    for (let attempt = 0; attempt < 2; attempt++) {
      if (++requests > maxRequests) throw new Error('Calendar operation request limit reached');
      const access = await tokens.get(account, signal);
      const url = new URL(path, CALENDAR_ROOT);
      for (const [k, v] of Object.entries(params))
        if (v !== undefined) url.searchParams.set(k, String(v));
      try {
        return await googleJson(
          url.toString(),
          {
            method,
            headers: headers(access, body !== undefined),
            body: body === undefined ? undefined : JSON.stringify(body),
            signal,
          },
          { fetchImpl, maxBytes: 2 * 1024 * 1024 },
        );
      } catch (err) {
        if (err.status === 401 && attempt === 0) {
          tokens.invalidate(account);
          continue;
        }
        if (err.status === 401)
          throw new Error(
            `Google Calendar login needed; run CAL_ACCOUNTS=${account.id} node index.js auth ${account.id} --calendar --client FILE`,
          );
        if (err.status === 403)
          throw new Error(
            'Google Calendar access denied; confirm the Calendar API is enabled, the login covers this calendar (run auth --calendar again after changing calendars), and you have access to it',
          );
        if (err.status === 404)
          throw new Error(
            'Event or calendar not found; if a created calendar was deleted, run auth --calendar again to recreate it',
          );
        if (err.status === 409) throw new Error('An event with this uid already exists');
        if (err.status === 429) throw new Error('Google Calendar rate limit reached; retry later');
        throw err;
      }
    }
  }

  /**
   * Resolve a calendar name from accounts.json (or, with "*", a calendar id) to what the account
   * may do with it. Nothing outside the configured list is ever requested.
   * @param {string} [name] Omit when the account has exactly one configured calendar.
   */
  async function calendar(name) {
    const named = configured(account).filter(([k]) => k !== '*');
    if (name === undefined) {
      if (named.length !== 1)
        throw new Error(
          `Name a calendar for "${account.id}": ${named.map(([k]) => k).join(', ') || '(any calendar id)'}`,
        );
      [[name]] = named;
    }
    if (typeof name !== 'string') throw new Error('Invalid calendar name');
    let key = name;
    let c = account.calendars?.[name];
    if (!c || name === '*') {
      // A raw id: a configured calendar's own rules win over the "*" entry.
      const match = named.find(([, cfg]) => cfg.id === name);
      if (match) [key, c] = match;
      else if (account.calendars?.['*'] && ANY_ID_RE.test(name)) c = account.calendars['*'];
      else
        throw new Error(
          `Calendar "${name.slice(0, 60)}" is not configured for "${account.id}". Configured: ${named.map(([k]) => k).join(', ')}`,
        );
    }
    let id = c.id ?? (c.create ? undefined : name);
    if (c.create) {
      await tokens.get(account, signal);
      id = tokens.metadata(account).calendar_ids?.[key];
      if (typeof id !== 'string' || !CREATED_ID_RE.test(id))
        throw new Error(
          `Calendar "${key}" has not been created yet; run CAL_ACCOUNTS=${account.id} node index.js auth ${account.id} --calendar --client FILE`,
        );
    }
    const base = `calendars/${encodeURIComponent(id)}`;
    return {
      key,
      id,
      kind: c.kind,
      writable: c.access === 'write',
      /** @param {'GET'|'POST'|'PATCH'|'DELETE'} method @param {string} resource '', 'events', 'events/import' or 'events/<id>' */
      call(method, resource, options) {
        if (
          !(
            resource === '' ||
            resource === 'events' ||
            resource === 'events/import' ||
            (resource.startsWith('events/') && EVENT_ID_RE.test(resource.slice(7)))
          )
        )
          throw new Error('Calendar resource refused');
        if (method !== 'GET' && c.access !== 'write')
          throw new Error(`Calendar "${key}" is read-only for "${account.id}"`);
        return request(method, `${base}${resource ? `/${resource}` : ''}`, options);
      },
    };
  }

  return { request, calendar };
}

/** @type {{ tokens?: ReturnType<typeof createTokenManager>, fetchImpl?: typeof fetch }} */
let deps = {};
/** Test seam: route operations through a fake token manager and fetch. */
export function configureCalendar(next = {}) {
  deps = next;
}

/**
 * @template T
 * @param {import('./types.js').Account} account
 * @param {(api: ReturnType<typeof createCalendarClient>) => Promise<T>} fn
 * @returns {Promise<T>}
 */
export async function withCalendar(account, fn, { maxRequests = 100, timeoutMs = 60000 } = {}) {
  if (!account.calendars) throw new Error(`No calendars configured for "${account.id}"`);
  return withOperationSlot(async () => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      return await fn(
        createCalendarClient(account, { ...deps, signal: controller.signal, maxRequests }),
      );
    } finally {
      controller.abort();
      clearTimeout(timer);
    }
  });
}

async function findByUid(cal, uid) {
  const data = await cal.call('GET', 'events', {
    params: { iCalUID: checkUid(uid), showDeleted: false, maxResults: 10 },
  });
  const items = (Array.isArray(data.items) ? data.items : []).filter(
    (e) => !e.recurringEventId && e.status !== 'cancelled',
  );
  if (items.length > 1) throw new Error('Several events share this uid; fix it in Google Calendar');
  const found = items[0] || null;
  if (found && !EVENT_ID_RE.test(found.id))
    throw new Error('Google returned an unexpected event id');
  return found;
}

/** Real meetings and special Google event types are never changed here. */
function assertEditable(event) {
  if (Array.isArray(event.attendees) && event.attendees.length)
    throw new Error('This event has guests; change it in Google Calendar instead');
  if (event.eventType && event.eventType !== 'default')
    throw new Error(`This is a ${event.eventType} event; change it in Google Calendar instead`);
}

// --- Operations (take an Account; used by index.js and other local tools) ----------

/**
 * The account's configured calendars; with "*", also every calendar the account can see.
 * @param {import('./types.js').Account} account
 */
export async function listCalendars(account) {
  return withCalendar(account, async (api) => {
    /** @type {{ calendar: string, access: string, kind?: string, name?: string, id?: string, problem?: string }[]} */
    const calendars = [];
    for (const [key, c] of configured(account)) {
      if (key === '*') continue;
      try {
        const cal = await api.calendar(key);
        calendars.push({
          calendar: key,
          access: c.access,
          ...(c.kind ? { kind: c.kind } : {}),
          ...(c.create ? { name: c.create } : { id: cal.id }),
        });
      } catch (err) {
        calendars.push({ calendar: key, access: c.access, problem: err.message });
      }
    }
    if (!account.calendars['*']) return { calendars };
    const data = await api.request('GET', 'users/me/calendarList', {
      params: { maxResults: 250, showHidden: false },
    });
    const visible = (Array.isArray(data.items) ? data.items : [])
      .filter((c) => typeof c.id === 'string' && ANY_ID_RE.test(c.id))
      .map((c) => ({
        id: c.id,
        name: String(c.summaryOverride || c.summary || ''),
        google_role: String(c.accessRole || ''),
        ...(c.primary ? { primary: true } : {}),
      }));
    return { calendars, any_calendar_access: account.calendars['*'].access, visible };
  });
}

/**
 * Events in a date range on one calendar. expand (default) lists each occurrence of a recurring
 * event in the range; expand:false lists series as stored, with their RRULEs.
 * @param {import('./types.js').Account} account
 * @param {{ calendar?: string, from?: string, to?: string, query?: string, expand?: boolean, limit?: number }} [options]
 */
export async function listEvents(
  account,
  { calendar, from, to, query, expand = true, limit = 100 } = {},
) {
  for (const [k, v] of Object.entries({ from, to }))
    if (v !== undefined && !isCalendarDate(v)) throw new Error(`${k} must be YYYY-MM-DD`);
  if (query !== undefined) text(query, 'query', 200);
  const n = Math.max(1, Math.min(250, Number(limit) || 100));
  const start = from ?? (expand ? todayIn() : undefined);
  const end = to ?? (expand && start ? addDays(start, 90) : undefined);
  return withCalendar(account, async (api) => {
    const cal = await api.calendar(calendar);
    const data = await cal.call('GET', 'events', {
      params: {
        singleEvents: expand,
        ...(expand ? { orderBy: 'startTime' } : {}),
        timeMin: start ? zonedToUtc(start) : undefined,
        timeMax: end ? zonedToUtc(end) : undefined,
        q: query,
        maxResults: n,
        showDeleted: false,
      },
    });
    const items = Array.isArray(data.items) ? data.items : [];
    return {
      calendar: cal.key,
      from: start ?? null,
      to: end ?? null,
      expanded: expand,
      returned: items.length,
      more_available: Boolean(data.nextPageToken),
      events: items
        .filter((e) => e.status !== 'cancelled')
        .map((e) => normalize(e, cal.key, cal.kind)),
    };
  });
}

/** @param {import('./types.js').Account} account @param {{ calendar?: string, uid: string }} options */
export async function getEvent(account, { calendar, uid }) {
  return withCalendar(account, async (api) => {
    const cal = await api.calendar(calendar);
    const found = await findByUid(cal, uid);
    if (!found) throw new Error(`No event with this uid in calendar "${cal.key}"`);
    return { event: normalize(found, cal.key, cal.kind) };
  });
}

/**
 * @typedef {object} EventInput
 * @property {string} [calendar]
 * @property {string} [title]
 * @property {string} [date] All-day, YYYY-MM-DD.
 * @property {string} [end_date] Last day of a multi-day all-day event, inclusive.
 * @property {string} [date_time] Timed, YYYY-MM-DDTHH:MM in America/Los_Angeles.
 * @property {string} [end_date_time]
 * @property {string} [location]
 * @property {string} [notes]
 * @property {string} [body] Deadlines calendars: agency tag such as CA-FTB.
 * @property {string} [recurrence] RRULE, "" to clear.
 * @property {string[]} [reminders] e.g. ["28d","7d"]; omitted: calendar default (deadlines: 28d, 7d).
 * @property {string} [slug] Deadlines calendars: stable uid part.
 * @property {string} [uid] Keep this iCalendar UID (imported via events.import).
 */

/** @param {import('./types.js').Account} account @param {EventInput} input */
export async function addEvent(account, input) {
  if (input.notes !== undefined) text(input.notes, 'notes', 4000, { multiline: true });
  if (input.location !== undefined) text(input.location, 'location', 500);
  if (input.body !== undefined && !BODY_RE.test(input.body))
    throw new Error('body must be an agency tag such as IRS, CA-FTB or DE');
  return withCalendar(account, async (api) => {
    const cal = await api.calendar(input.calendar);
    if (!cal.writable) throw new Error(`Calendar "${cal.key}" is read-only for "${account.id}"`);
    const deadlines = cal.kind === 'deadlines';
    const entity = entityOf(account);
    let uid = input.uid === undefined ? undefined : checkUid(input.uid);
    if (deadlines && !uid) {
      const slug =
        input.slug ??
        `${String(input.title || '')
          .toLowerCase()
          .replace(/^[a-z0-9]+:\s*/, '')
          .replace(/[^a-z0-9]+/g, '-')
          .replace(/^-+|-+$/g, '')
          .slice(0, 48)
          .replace(/-+$/, '')}-${String(input.date || input.date_time || '').slice(0, 4)}`;
      if (!SLUG_RE.test(slug)) throw new Error('slug must be lowercase letters, digits and dashes');
      uid = `${entity}-${slug}@compliance`;
    }
    const event = {
      summary: title(input.title, deadlines ? entity : null),
      description: deadlines
        ? composeDescription(input.notes, input.body, entity)
        : (input.notes ?? ''),
      ...(input.location ? { location: input.location } : {}),
      ...when(input, deadlines ? 30 : 60),
      ...(input.recurrence ? { recurrence: recurrence(input.recurrence) } : {}),
      reminders:
        input.reminders || deadlines
          ? reminders(input.reminders ?? DEFAULT_REMINDERS)
          : { useDefault: true },
      ...(deadlines
        ? {
            transparency: 'transparent',
            visibility: 'private',
            extendedProperties: privateProps(uid, entity, input.body),
          }
        : {}),
    };
    let created;
    if (uid) {
      if (await findByUid(cal, uid))
        throw new Error(`An event with uid ${uid} already exists; update it instead`);
      // events.import keeps the supplied iCalUID (events.insert would replace it).
      created = await cal.call('POST', 'events/import', { body: { ...event, iCalUID: uid } });
    } else {
      created = await cal.call('POST', 'events', {
        params: { sendUpdates: 'none' },
        body: event,
      });
    }
    return { created: normalize(created, cal.key, cal.kind) };
  });
}

/**
 * Patch an event. Omitted fields are unchanged; recurrence "" makes it one-off.
 * @param {import('./types.js').Account} account
 * @param {EventInput & { uid: string }} input
 */
export async function updateEvent(account, input) {
  if (input.notes !== undefined) text(input.notes, 'notes', 4000, { multiline: true });
  if (input.location !== undefined) text(input.location, 'location', 500);
  if (input.body !== undefined && input.body !== '' && !BODY_RE.test(input.body))
    throw new Error('body must be an agency tag such as IRS, CA-FTB or DE');
  return withCalendar(account, async (api) => {
    const cal = await api.calendar(input.calendar);
    if (!cal.writable) throw new Error(`Calendar "${cal.key}" is read-only for "${account.id}"`);
    const deadlines = cal.kind === 'deadlines';
    const entity = entityOf(account);
    const found = await findByUid(cal, input.uid);
    if (!found) throw new Error(`No event with this uid in calendar "${cal.key}"`);
    assertEditable(found);
    const patch = {};
    if (input.title !== undefined) patch.summary = title(input.title, deadlines ? entity : null);
    if (input.date !== undefined || input.date_time !== undefined)
      Object.assign(patch, when(input, deadlines ? 30 : 60));
    if (input.location !== undefined) patch.location = input.location;
    if (input.recurrence !== undefined) patch.recurrence = recurrence(input.recurrence);
    if (input.reminders !== undefined) patch.reminders = reminders(input.reminders);
    if (deadlines) {
      const meta = parseMeta(found.description);
      const body = input.body === undefined ? meta.body : input.body || null;
      const notes = input.notes === undefined ? meta.notes : input.notes;
      if (input.notes !== undefined || input.body !== undefined || !meta.entity)
        patch.description = composeDescription(notes, body, entity);
      patch.extendedProperties = privateProps(found.iCalUID, entity, body);
    } else if (input.notes !== undefined) patch.description = input.notes;
    if (!Object.keys(patch).filter((k) => k !== 'extendedProperties').length)
      throw new Error('Nothing to update');
    const updated = await cal.call('PATCH', `events/${found.id}`, {
      params: { sendUpdates: 'none' },
      body: patch,
    });
    return { updated: normalize(updated, cal.key, cal.kind) };
  });
}

/** @param {import('./types.js').Account} account @param {{ calendar?: string, uid: string }} options */
export async function deleteEvent(account, { calendar, uid }) {
  return withCalendar(account, async (api) => {
    const cal = await api.calendar(calendar);
    if (!cal.writable) throw new Error(`Calendar "${cal.key}" is read-only for "${account.id}"`);
    const found = await findByUid(cal, uid);
    if (!found) throw new Error(`No event with this uid in calendar "${cal.key}"`);
    assertEditable(found);
    await cal.call('DELETE', `events/${found.id}`, { params: { sendUpdates: 'none' } });
    return {
      deleted: { calendar: cal.key, uid: found.iCalUID, summary: String(found.summary || '') },
    };
  });
}

/**
 * Convert parsed .ics events (ics.js) into import bodies, preserving UIDs, summaries,
 * recurrence and alarms where Google can represent them, and reporting where it cannot.
 * @param {import('./types.js').Account} account
 * @param {any[]} events
 * @param {{ deadlines?: boolean }} [options]
 */
export function planImport(account, events, { deadlines = true } = {}) {
  const entity = entityOf(account);
  return events.map((ev) => {
    const notes = [...ev.problems];
    const minutes = [];
    for (const a of ev.alarms) {
      if (a.minutes < 0)
        notes.push(`alarm ${a.trigger} is after the start; Google cannot store it`);
      else if (a.minutes > MAX_REMINDER_MINUTES) {
        notes.push(`alarm ${a.trigger} exceeds Google's 28-day limit; set to 28 days`);
        minutes.push(MAX_REMINDER_MINUTES);
      } else minutes.push(a.minutes);
    }
    const unique = [...new Set(minutes)].sort((x, y) => y - x);
    if (unique.length > 5) notes.push(`only the first 5 of ${unique.length} alarms kept`);
    if (deadlines && !String(ev.summary || '').startsWith(`${entity.toUpperCase()}:`))
      notes.push(`summary lacks the "${entity.toUpperCase()}:" prefix`);
    const meta = parseMeta(ev.description || '');
    const start = ev.start;
    const end = ev.end || (start.date ? { date: addDays(start.date, 1) } : start);
    const zone = (t) => (t.dateTime && !t.timeZone ? { ...t, timeZone: TIME_ZONE } : t);
    const body = {
      iCalUID: checkUid(ev.uid),
      summary: ev.summary || '',
      description:
        !deadlines || meta.entity
          ? ev.description || ''
          : composeDescription(ev.description, null, entity),
      start: zone(start),
      end: zone(end),
      recurrence: ev.recurrence,
      reminders: {
        useDefault: false,
        overrides: unique.slice(0, 5).map((n) => ({ method: 'popup', minutes: n })),
      },
      ...(deadlines
        ? {
            transparency: 'transparent',
            visibility: 'private',
            extendedProperties: privateProps(ev.uid, entity, meta.body),
          }
        : {}),
    };
    return { uid: ev.uid, summary: body.summary, body, notes };
  });
}

/**
 * Import parsed .ics events into one calendar. Without apply it only reports; existing UIDs are
 * always skipped.
 * @param {import('./types.js').Account} account
 * @param {any[]} events
 * @param {{ calendar?: string, apply?: boolean }} [options]
 */
export async function importEvents(account, events, { calendar, apply = false } = {}) {
  return withCalendar(
    account,
    async (api) => {
      const cal = await api.calendar(calendar);
      if (!cal.writable) throw new Error(`Calendar "${cal.key}" is read-only for "${account.id}"`);
      const plan = planImport(account, events, { deadlines: cal.kind === 'deadlines' });
      const items = [];
      for (const p of plan) {
        const exists = await findByUid(cal, p.uid);
        let status = exists ? 'exists, skipped' : apply ? 'imported' : 'would import';
        if (!exists && apply) {
          try {
            await cal.call('POST', 'events/import', { body: p.body });
          } catch (err) {
            status = `failed: ${err.message}`;
          }
        }
        items.push({ uid: p.uid, summary: p.summary, status, notes: p.notes });
      }
      const count = (s) => items.filter((i) => i.status === s).length;
      return {
        calendar: cal.key,
        applied: apply,
        total: items.length,
        imported: count('imported'),
        would_import: count('would import'),
        skipped_existing: count('exists, skipped'),
        failed: items.filter((i) => i.status.startsWith('failed')).length,
        items,
      };
    },
    { maxRequests: events.length * 3 + 10, timeoutMs: 300000 },
  );
}
