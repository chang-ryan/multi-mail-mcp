/**
 * Google Calendar deadlines: one private, app-created "Deadlines [ENTITY]" calendar per account.
 *
 * Scope is calendar.app.created, so this code can reach only calendars it created: never a
 * primary calendar, a shared calendar or a meeting. Deadlines are internal: no attendees can be
 * written and every change sends no notifications. The MCP server (index.js) and the
 * compliance hub both call the exported operations.
 *
 * Event format (shared with the hub and the Proton .ics files):
 * - UID is the obligation id: existing UIDs are preserved, new ones are <entity>-<slug>@compliance.
 * - SUMMARY starts with "<ENTITY>: ".
 * - DESCRIPTION ends with a machine-readable line "Body: CA-FTB · Entity: acme" ("Body" optional).
 * - Recurrence stays as RRULEs; status lives in the hub, never in the calendar.
 */

import { CALENDAR_ROOT, googleJson, USERINFO_URL } from './google-http.js';
import { createTokenManager } from './oauth.js';
import { withOperationSlot } from './runtime.js';
import { isCalendarDate } from './security.js';

export const CAL_SERVICE = 'multi-mail-mcp.gcal-oauth';
export const CAL_SCOPE = 'https://www.googleapis.com/auth/calendar.app.created';
export const TIME_ZONE = 'America/Los_Angeles';
export const DEFAULT_REMINDERS = ['28d', '7d'];
const MAX_REMINDER_MINUTES = 40320; // Google's limit: four weeks.
const CAL_ID_RE = /^[a-z0-9]{1,128}@group\.calendar\.google\.com$/;
const UID_RE = /^[A-Za-z0-9][A-Za-z0-9@._-]{0,254}$/;
const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const BODY_RE = /^[A-Z][A-Z0-9-]{0,15}$/;
const RRULE_RE = /^FREQ=(?:YEARLY|MONTHLY|WEEKLY|DAILY)(?:;[A-Z]+=[A-Z0-9,+-]+){0,8}$/;
const META_RE = /(?:^|\n)(?:Body: ([A-Z][A-Z0-9-]{0,15}) · )?Entity: ([a-z][a-z0-9]{0,15})\s*$/;
// biome-ignore lint/suspicious/noControlCharactersInRegex: Reject control characters in event text.
const CONTROL = /[\x00-\x08\x0b-\x1f\x7f]/;

/** @type {import('./oauth.js').OAuthProfile} */
export const CALENDAR = {
  name: 'Google Calendar',
  service: CAL_SERVICE,
  scopes: ['openid', 'https://www.googleapis.com/auth/userinfo.email', CAL_SCOPE],
  requestScope: `openid email ${CAL_SCOPE}`,
  scopeError:
    'Calendar grant must contain only openid, email and calendar.app.created; revoke it and authorize again',
  command: 'CAL_ACCOUNTS=%s node index.js auth %s --calendar',
  metadata: ['calendar_id'],
  async identity(accessToken, fetchImpl, signal) {
    const info = await googleJson(
      USERINFO_URL,
      { headers: { Authorization: `Bearer ${accessToken}` }, signal },
      { fetchImpl, maxBytes: 65536 },
    );
    if (info.email_verified !== true) throw new Error('Google account email is not verified');
    return info.email;
  },
  /** Reuse the account's Deadlines calendar from a previous login, or create it. */
  async prepare(accessToken, fetchImpl, previous, account) {
    const entity = entityOf(account);
    const headers = { Authorization: `Bearer ${accessToken}` };
    const known = previous?.calendar_id;
    if (typeof known === 'string' && CAL_ID_RE.test(known)) {
      try {
        const cal = await googleJson(
          `${CALENDAR_ROOT}calendars/${encodeURIComponent(known)}`,
          { headers },
          { fetchImpl },
        );
        return { calendar_id: known, calendar_name: String(cal.summary || '') };
      } catch (err) {
        if (err.status !== 403 && err.status !== 404) throw err;
      }
    }
    const name = `Deadlines [${entity.toUpperCase()}]`;
    const cal = await googleJson(
      `${CALENDAR_ROOT}calendars`,
      {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          summary: name,
          timeZone: TIME_ZONE,
          description: 'Internal deadlines and reminders, managed by multi-mail-mcp. No guests.',
        }),
      },
      { fetchImpl },
    );
    if (typeof cal.id !== 'string' || !CAL_ID_RE.test(cal.id))
      throw new Error('Google returned an unexpected calendar id');
    return { calendar_id: cal.id, calendar_name: name };
  },
};

export const calendarTokens = createTokenManager({ profile: CALENDAR });

/** @param {import('./types.js').Account} account */
export const entityOf = (account) => account.entity || account.id;

// --- Validation (the hub calls these operations directly, not only through MCP) ---------

function text(value, name, max, { multiline = false } = {}) {
  if (typeof value !== 'string' || value.length > max || (!multiline && /[\r\n]/.test(value)))
    throw new Error(`${name} must be text of at most ${max} characters`);
  if (CONTROL.test(value)) throw new Error(`${name} contains control characters`);
  return value;
}

function checkUid(uid) {
  if (typeof uid !== 'string' || !UID_RE.test(uid)) throw new Error('Invalid deadline uid');
  return uid;
}

/** "28d", "7d", "2h", "30m" → minutes before the deadline. */
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

function prefixed(title, entity) {
  const prefix = `${entity.toUpperCase()}:`;
  const t = text(title, 'title', 300).trim();
  if (!t) throw new Error('title is required');
  return t.startsWith(prefix) ? t : `${prefix} ${t}`;
}

/**
 * Start/end for an all-day `date` (YYYY-MM-DD) or a timed `date_time` (YYYY-MM-DDTHH:MM, local).
 * @param {{ date?: string, date_time?: string }} input
 */
function when({ date, date_time }) {
  if (date !== undefined && date_time !== undefined)
    throw new Error('Give either date (all-day) or date_time, not both');
  if (date !== undefined) {
    if (typeof date !== 'string' || !isCalendarDate(date))
      throw new Error('date must be YYYY-MM-DD');
    return { start: { date }, end: { date: addDays(date, 1) } };
  }
  if (
    typeof date_time !== 'string' ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(date_time) ||
    !isCalendarDate(date_time.slice(0, 10)) ||
    Number(date_time.slice(11, 13)) > 23 ||
    Number(date_time.slice(14, 16)) > 59
  )
    throw new Error('date_time must be YYYY-MM-DDTHH:MM in the calendar time zone');
  const start = `${date_time}:00`;
  return {
    start: { dateTime: start, timeZone: TIME_ZONE },
    end: { dateTime: addMinutesLocal(start, 30), timeZone: TIME_ZONE },
  };
}

const privateProps = (uid, entity, body) => ({
  private: { obligation_id: uid, entity, ...(body ? { body } : {}), managed_by: 'multi-mail-mcp' },
});

/** Normalized deadline, as the MCP tools and the hub see it. */
export function normalize(e) {
  const allDay = Boolean(e.start?.date);
  const description = typeof e.description === 'string' ? e.description : '';
  const meta = parseMeta(description);
  const priv = e.extendedProperties?.private || {};
  const rec = Array.isArray(e.recurrence) ? e.recurrence.map(String) : [];
  return {
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
    entity: meta.entity || priv.entity || null,
    body: meta.body || priv.body || null,
    notes: meta.notes,
    description,
    reminders: Array.isArray(e.reminders?.overrides)
      ? e.reminders.overrides.map((r) => formatMinutes(Number(r.minutes)))
      : [],
    source: 'google',
  };
}

// --- Client ------------------------------------------------------------------------

const EVENT_ID = /^[a-z0-9_]{1,1024}$/;

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
   * @param {string} resource Relative to this account's Deadlines calendar: '', 'events', 'events/import', 'events/<id>'.
   * @param {{ params?: Record<string, unknown>, body?: unknown }} [options]
   */
  async function call(method, resource, { params = {}, body } = {}) {
    if (!/^(?:|events|events\/import|events\/[a-z0-9_]{1,1024})$/.test(resource))
      throw new Error('Calendar resource refused');
    for (let attempt = 0; attempt < 2; attempt++) {
      if (++requests > maxRequests) throw new Error('Calendar operation request limit reached');
      const access = await tokens.get(account, signal);
      const calendarId = tokens.metadata(account).calendar_id;
      if (typeof calendarId !== 'string' || !CAL_ID_RE.test(calendarId))
        throw new Error(
          `No Deadlines calendar recorded for "${account.id}"; run CAL_ACCOUNTS=${account.id} node index.js auth ${account.id} --calendar --client FILE`,
        );
      const url = new URL(
        `calendars/${encodeURIComponent(calendarId)}${resource ? `/${resource}` : ''}`,
        CALENDAR_ROOT,
      );
      for (const [k, v] of Object.entries(params))
        if (v !== undefined) url.searchParams.set(k, String(v));
      try {
        return await googleJson(
          url.toString(),
          {
            method,
            headers: {
              Authorization: `Bearer ${access}`,
              ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
            },
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
            'Google Calendar access denied; confirm the Calendar API is enabled in the Google Cloud project and calendar.app.created was granted',
          );
        if (err.status === 404)
          throw new Error(
            'Deadline or Deadlines calendar not found; if the calendar was deleted, run auth again to recreate it',
          );
        if (err.status === 409) throw new Error('A deadline with this uid already exists');
        if (err.status === 429) throw new Error('Google Calendar rate limit reached; retry later');
        throw err;
      }
    }
  }
  return { call };
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
  if (account.type !== 'gmail') throw new Error('Calendar access is Google-only for now');
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

async function findByUid(api, uid) {
  const data = await api.call('GET', 'events', {
    params: { iCalUID: checkUid(uid), showDeleted: false, maxResults: 10 },
  });
  const items = (Array.isArray(data.items) ? data.items : []).filter(
    (e) => !e.recurringEventId && e.status !== 'cancelled',
  );
  if (items.length > 1) throw new Error('Several events share this uid; fix it in Google Calendar');
  const found = items[0] || null;
  if (found && !EVENT_ID.test(found.id)) throw new Error('Google returned an unexpected event id');
  return found;
}

// --- Operations (take an Account; used by index.js and the hub) ------------------

/** @param {import('./types.js').Account} account */
export async function calendarInfo(account) {
  return withCalendar(account, async (api) => {
    const cal = await api.call('GET', '');
    return { calendar: String(cal.summary || ''), time_zone: String(cal.timeZone || '') };
  });
}

/**
 * Deadlines in a date range. expand (default) returns each occurrence of a recurring deadline
 * in the range; expand:false returns series as stored, with their RRULEs.
 * @param {import('./types.js').Account} account
 * @param {{ from?: string, to?: string, query?: string, expand?: boolean, limit?: number }} [options]
 */
export async function listDeadlines(account, { from, to, query, expand = true, limit = 100 } = {}) {
  for (const [k, v] of Object.entries({ from, to }))
    if (v !== undefined && !isCalendarDate(v)) throw new Error(`${k} must be YYYY-MM-DD`);
  if (query !== undefined) text(query, 'query', 200);
  const n = Math.max(1, Math.min(250, Number(limit) || 100));
  const start = from ?? (expand ? todayIn() : undefined);
  const end = to ?? (expand && start ? addDays(start, 90) : undefined);
  return withCalendar(account, async (api) => {
    const data = await api.call('GET', 'events', {
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
      from: start ?? null,
      to: end ?? null,
      expanded: expand,
      returned: items.length,
      more_available: Boolean(data.nextPageToken),
      deadlines: items.filter((e) => e.status !== 'cancelled').map(normalize),
    };
  });
}

/** @param {import('./types.js').Account} account @param {{ uid: string }} options */
export async function getDeadline(account, { uid }) {
  return withCalendar(account, async (api) => {
    const found = await findByUid(api, uid);
    if (!found) throw new Error('No deadline with this uid in the Deadlines calendar');
    return { deadline: normalize(found) };
  });
}

/**
 * @param {import('./types.js').Account} account
 * @param {{ title: string, date?: string, date_time?: string, notes?: string, body?: string, recurrence?: string, reminders?: string[], slug?: string, uid?: string }} input
 */
export async function addDeadline(account, input) {
  const entity = entityOf(account);
  let uid;
  if (input.uid !== undefined) uid = checkUid(input.uid);
  else {
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
  if (input.body !== undefined && !BODY_RE.test(input.body))
    throw new Error('body must be an agency tag such as IRS, CA-FTB or DE');
  if (input.notes !== undefined) text(input.notes, 'notes', 4000, { multiline: true });
  const event = {
    iCalUID: uid,
    summary: prefixed(input.title, entity),
    description: composeDescription(input.notes, input.body, entity),
    ...when(input),
    recurrence: input.recurrence === undefined ? [] : recurrence(input.recurrence),
    reminders: reminders(input.reminders ?? DEFAULT_REMINDERS),
    transparency: 'transparent',
    visibility: 'private',
    extendedProperties: privateProps(uid, entity, input.body),
  };
  return withCalendar(account, async (api) => {
    if (await findByUid(api, uid))
      throw new Error(`A deadline with uid ${uid} already exists; update it instead`);
    // events.import keeps the supplied iCalUID (events.insert would replace it).
    const created = await api.call('POST', 'events/import', { body: event });
    return { created: normalize(created) };
  });
}

/**
 * Patch a deadline. Omitted fields are unchanged; recurrence "" clears it.
 * @param {import('./types.js').Account} account
 * @param {{ uid: string, title?: string, date?: string, date_time?: string, notes?: string, body?: string, recurrence?: string, reminders?: string[] }} input
 */
export async function updateDeadline(account, input) {
  const entity = entityOf(account);
  if (input.body !== undefined && input.body !== '' && !BODY_RE.test(input.body))
    throw new Error('body must be an agency tag such as IRS, CA-FTB or DE');
  if (input.notes !== undefined) text(input.notes, 'notes', 4000, { multiline: true });
  const patch = {};
  if (input.title !== undefined) patch.summary = prefixed(input.title, entity);
  if (input.date !== undefined || input.date_time !== undefined) Object.assign(patch, when(input));
  if (input.recurrence !== undefined) patch.recurrence = recurrence(input.recurrence);
  if (input.reminders !== undefined) patch.reminders = reminders(input.reminders);
  return withCalendar(account, async (api) => {
    const found = await findByUid(api, input.uid);
    if (!found) throw new Error('No deadline with this uid in the Deadlines calendar');
    if (Array.isArray(found.attendees) && found.attendees.length)
      throw new Error('This event has guests; edit it in Google Calendar instead');
    const meta = parseMeta(found.description);
    const body = input.body === undefined ? meta.body : input.body || null;
    const notes = input.notes === undefined ? meta.notes : input.notes;
    patch.description = composeDescription(notes, body, entity);
    patch.extendedProperties = privateProps(found.iCalUID, entity, body);
    if (Object.keys(patch).length === 2 && input.notes === undefined && input.body === undefined)
      throw new Error('Nothing to update');
    const updated = await api.call('PATCH', `events/${found.id}`, {
      params: { sendUpdates: 'none' },
      body: patch,
    });
    return { updated: normalize(updated) };
  });
}

/** @param {import('./types.js').Account} account @param {{ uid: string }} options */
export async function deleteDeadline(account, { uid }) {
  return withCalendar(account, async (api) => {
    const found = await findByUid(api, uid);
    if (!found) throw new Error('No deadline with this uid in the Deadlines calendar');
    await api.call('DELETE', `events/${found.id}`, { params: { sendUpdates: 'none' } });
    return { deleted: { uid: found.iCalUID, summary: String(found.summary || '') } };
  });
}

/**
 * Convert parsed .ics events (ics.js) into import bodies, preserving UIDs, summaries,
 * recurrence and alarms where Google can represent them, and reporting where it cannot.
 */
export function planImport(account, events) {
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
    if (!String(ev.summary || '').startsWith(`${entity.toUpperCase()}:`))
      notes.push(`summary lacks the "${entity.toUpperCase()}:" prefix`);
    const meta = parseMeta(ev.description || '');
    const start = ev.start;
    const end = ev.end || (start.date ? { date: addDays(start.date, 1) } : start);
    const zone = (t) => (t.dateTime && !t.timeZone ? { ...t, timeZone: TIME_ZONE } : t);
    const body = {
      iCalUID: checkUid(ev.uid),
      summary: ev.summary || '',
      description: meta.entity ? ev.description : composeDescription(ev.description, null, entity),
      start: zone(start),
      end: zone(end),
      recurrence: ev.recurrence,
      reminders: {
        useDefault: false,
        overrides: unique.slice(0, 5).map((n) => ({ method: 'popup', minutes: n })),
      },
      transparency: 'transparent',
      visibility: 'private',
      extendedProperties: privateProps(ev.uid, entity, meta.body),
    };
    return { uid: ev.uid, summary: body.summary, body, notes };
  });
}

/**
 * Import planned events. Without apply it only reports; existing UIDs are always skipped.
 * @param {import('./types.js').Account} account
 */
export async function importDeadlines(account, events, { apply = false } = {}) {
  const plan = planImport(account, events);
  return withCalendar(
    account,
    async (api) => {
      const items = [];
      for (const p of plan) {
        const exists = await findByUid(api, p.uid);
        let status = exists ? 'exists, skipped' : apply ? 'imported' : 'would import';
        if (!exists && apply) {
          try {
            await api.call('POST', 'events/import', { body: p.body });
          } catch (err) {
            status = `failed: ${err.message}`;
          }
        }
        items.push({ uid: p.uid, summary: p.summary, status, notes: p.notes });
      }
      const count = (s) => items.filter((i) => i.status === s).length;
      return {
        applied: apply,
        total: items.length,
        imported: count('imported'),
        would_import: count('would import'),
        skipped_existing: count('exists, skipped'),
        failed: items.filter((i) => i.status.startsWith('failed')).length,
        items,
      };
    },
    { maxRequests: plan.length * 3 + 10, timeoutMs: 300000 },
  );
}
