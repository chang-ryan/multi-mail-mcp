import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import {
  addEvent,
  calendarProfile,
  composeDescription,
  configureCalendar,
  deleteEvent,
  importEvents,
  listCalendars,
  listEvents,
  parseMeta,
  planImport,
  reminderMinutes,
  SCOPES,
  scopesFor,
  updateEvent,
  zonedToUtc,
} from '../calendar-core.js';
import { CALENDAR_ROOT, googleJson, USERINFO_URL } from '../google-http.js';
import { parseIcs, triggerMinutes } from '../ics.js';
import { authorize, validateScope } from '../oauth.js';

const repo = fileURLToPath(new URL('../', import.meta.url));
const CAL = 'abc123@group.calendar.google.com';
const SHARED = 'board@group.calendar.google.com';
const account = {
  id: 'acme',
  type: 'gmail',
  user: 'ops@example.test',
  entity: 'acme',
  calendars: {
    deadlines: { create: 'Deadlines [ACME]', access: 'write', kind: 'deadlines' },
    travel: { create: 'Travel', access: 'write' },
    main: { id: 'primary', access: 'read' },
  },
};
const json = (value, status = 200) => new Response(JSON.stringify(value), { status });

/** Fake Calendar API: records requests and keeps events per calendar by iCalUID. */
function fakeCalendar(initial = {}) {
  const calendars = new Map(
    Object.entries(initial).map(([id, list]) => [id, new Map(list.map((e) => [e.iCalUID, e]))]),
  );
  const requests = [];
  let next = 1;
  const fetchImpl = async (url, options = {}) => {
    const u = new URL(url);
    const method = options.method || 'GET';
    const body = options.body ? JSON.parse(options.body) : undefined;
    requests.push({ method, path: u.pathname, params: Object.fromEntries(u.searchParams), body });
    assert.equal(options.headers.Authorization, 'Bearer access');
    if (u.pathname === '/calendar/v3/users/me/calendarList')
      return json({
        items: [{ id: 'me@example.test', summary: 'Me', accessRole: 'owner', primary: true }],
      });
    const m = /^\/calendar\/v3\/calendars\/([^/]+)\/events(?:\/(.+))?$/.exec(u.pathname);
    if (!m) return json({}, 404);
    const calId = decodeURIComponent(m[1]);
    if (!calendars.has(calId)) calendars.set(calId, new Map());
    const events = calendars.get(calId);
    if (method === 'GET' && !m[2]) {
      const uid = u.searchParams.get('iCalUID');
      return json({ items: uid ? [events.get(uid)].filter(Boolean) : [...events.values()] });
    }
    if (method === 'POST' && (m[2] === 'import' || !m[2])) {
      const created = { iCalUID: `generated${next}@google.com`, ...body, id: `ev${next++}` };
      events.set(created.iCalUID, created);
      return json(created);
    }
    const found = [...events.values()].find((e) => e.id === m[2]);
    if (method === 'PATCH' && found) {
      Object.assign(found, body);
      return json(found);
    }
    if (method === 'DELETE' && found) {
      events.delete(found.iCalUID);
      return new Response(null, { status: 204 });
    }
    return json({ error: { message: 'not found' } }, 404);
  };
  const tokens = {
    get: async () => 'access',
    invalidate() {},
    metadata: () => ({
      calendar_ids: { deadlines: CAL, travel: 'trv456@group.calendar.google.com' },
    }),
  };
  return { calendars, requests, fetchImpl, tokens };
}

function withFake(t, initial) {
  const fake = fakeCalendar(initial);
  configureCalendar({ fetchImpl: fake.fetchImpl, tokens: /** @type {any} */ (fake.tokens) });
  t.after(() => configureCalendar());
  return fake;
}

test('scopes follow the configured calendars, and a grant must match them exactly', () => {
  const only = (calendars) => scopesFor(/** @type {any} */ ({ id: 'x', calendars }));
  assert.deepEqual(only({ d: { create: 'D', access: 'write' } }), [
    'openid',
    SCOPES.email,
    SCOPES.appCreated,
  ]);
  assert.deepEqual(only({ m: { id: 'primary', access: 'read' } }), [
    'openid',
    SCOPES.email,
    SCOPES.eventsRead,
  ]);
  assert.deepEqual(
    only({ d: { create: 'D', access: 'read' }, b: { id: SHARED, access: 'write' } }),
    ['openid', SCOPES.email, SCOPES.appCreated, SCOPES.events],
  );
  assert.deepEqual(only({ '*': { access: 'read' } }), [
    'openid',
    SCOPES.email,
    SCOPES.eventsRead,
    SCOPES.calendarList,
  ]);
  assert.throws(() => scopesFor(/** @type {any} */ ({ id: 'x' })), /No calendars configured/);

  const profile = calendarProfile(/** @type {any} */ (account));
  assert.equal(profile.requestScope, `openid email ${SCOPES.appCreated} ${SCOPES.eventsRead}`);
  validateScope(`${SCOPES.eventsRead} openid ${SCOPES.email} ${SCOPES.appCreated}`, profile);
  for (const bad of [
    `openid email ${SCOPES.appCreated}`, // config now needs more: run auth again
    `openid email ${SCOPES.appCreated} ${SCOPES.events}`, // broader than configured
    `openid email ${SCOPES.appCreated} ${SCOPES.eventsRead} https://www.googleapis.com/auth/gmail.readonly`,
  ])
    assert.throws(() => validateScope(bad, profile), /run auth --calendar again/);
  assert.throws(() => validateScope('openid email', undefined), /gmail.readonly/);
});

test('the HTTP layer allows only the event tool paths and methods', async () => {
  const ok = async () => json({});
  const cal = `${CALENDAR_ROOT}calendars/${encodeURIComponent(CAL)}`;
  for (const [url, method] of [
    [`${CALENDAR_ROOT}calendars`, 'POST'],
    [`${CALENDAR_ROOT}users/me/calendarList`, 'GET'],
    [cal, 'GET'],
    [`${cal}/events`, 'GET'],
    [`${cal}/events`, 'POST'],
    [`${cal}/events/import`, 'POST'],
    [`${cal}/events/ev1`, 'PATCH'],
    [`${cal}/events/ev1`, 'DELETE'],
    [`${CALENDAR_ROOT}calendars/primary/events`, 'GET'],
    [USERINFO_URL, 'GET'],
  ])
    await googleJson(url, { method }, { fetchImpl: ok });
  for (const [url, method] of [
    [cal, 'DELETE'],
    [cal, 'PATCH'],
    [`${cal}/acl`, 'POST'],
    [`${cal}/clear`, 'POST'],
    [`${cal}/events/ev1/move`, 'POST'],
    [`${cal}/events/quickAdd`, 'POST'],
    [`${cal}/events/watch`, 'POST'],
    [`${CALENDAR_ROOT}users/me/calendarList`, 'POST'],
    [`${CALENDAR_ROOT}users/me/settings`, 'GET'],
    [USERINFO_URL, 'POST'],
  ])
    await assert.rejects(googleJson(url, { method }, { fetchImpl: ok }), /refused/);
});

test('only configured calendars are reachable, read-only ones refuse writes, "*" allows ids', async (t) => {
  const fake = withFake(t);
  await listEvents(account, { calendar: 'main', from: '2027-01-01' });
  assert.match(fake.requests.at(-1).path, /calendars\/primary\/events$/);
  await assert.rejects(listEvents(account, { calendar: 'other' }), /not configured/);
  await assert.rejects(listEvents(account, { calendar: SHARED }), /not configured/);
  await assert.rejects(listEvents(account), /Name a calendar/);
  await assert.rejects(
    addEvent(account, { calendar: 'main', title: 'x', date: '2027-01-01' }),
    /read-only/,
  );
  const before = fake.requests.length;
  await assert.rejects(deleteEvent(account, { calendar: 'main', uid: 'x@y' }), /read-only/);
  assert.equal(fake.requests.length, before, 'refused before any request');

  const any = {
    ...account,
    calendars: { main: { id: 'primary', access: 'read' }, '*': { access: 'write' } },
  };
  await addEvent(any, { calendar: SHARED, title: 'Board dinner', date: '2027-02-01' });
  assert.match(fake.requests.at(-1).path, new RegExp(`${encodeURIComponent(SHARED)}/events$`));
  // A configured calendar's own (read-only) rule wins over "*".
  await assert.rejects(
    addEvent(any, { calendar: 'primary', title: 'x', date: '2027-01-01' }),
    /read-only/,
  );
  const listed = await listCalendars(any);
  assert.equal(listed.visible[0].primary, true);
});

test('ics parsing unfolds, unescapes and reads dates, rules and alarms', () => {
  const ics = [
    'BEGIN:VCALENDAR',
    'BEGIN:VEVENT',
    'UID:acme-a@acme-compliance',
    'DTSTART;VALUE=DATE:20270415',
    'DTEND;VALUE=DATE:20270416',
    'RRULE:FREQ=YEARLY;INTERVAL=2',
    'SUMMARY:ACME: File\\, then pay',
    'DESCRIPTION:Line one\\nline two that is fo',
    ' lded',
    'BEGIN:VALARM',
    'TRIGGER:-P45D',
    'END:VALARM',
    'BEGIN:VALARM',
    'TRIGGER:PT9H',
    'END:VALARM',
    'BEGIN:VALARM',
    'TRIGGER:-P7D',
    'END:VALARM',
    'ATTENDEE:mailto:x@example.test',
    'END:VEVENT',
    'BEGIN:VEVENT',
    'SUMMARY:no uid',
    'END:VEVENT',
    'END:VCALENDAR',
  ].join('\r\n');
  const { events, warnings } = parseIcs(ics);
  assert.equal(events.length, 1);
  assert.equal(warnings.length, 1);
  const [e] = events;
  assert.equal(e.summary, 'ACME: File, then pay');
  assert.equal(e.description, 'Line one\nline two that is folded');
  assert.deepEqual(e.start, { date: '2027-04-15' });
  assert.deepEqual(e.recurrence, ['RRULE:FREQ=YEARLY;INTERVAL=2']);
  assert.deepEqual(
    e.alarms.map((a) => a.minutes),
    [64800, -540, 10080],
  );
  assert.match(e.problems[0], /ATTENDEE ignored/);
  assert.equal(triggerMinutes('-P1W'), 10080);
  assert.equal(triggerMinutes('-PT2H30M'), 150);
  assert.equal(triggerMinutes('garbage'), null);

  const [plan] = planImport(account, events);
  assert.equal(plan.body.iCalUID, 'acme-a@acme-compliance');
  assert.deepEqual(
    plan.body.reminders.overrides.map((o) => o.minutes),
    [40320, 10080],
  );
  assert.ok(plan.notes.some((n) => /28-day limit/.test(n)));
  assert.ok(plan.notes.some((n) => /after the start/.test(n)));
  assert.equal(parseMeta(plan.body.description).entity, 'acme');
  assert.equal(plan.body.attendees, undefined);
  const [plain] = planImport(account, events, { deadlines: false });
  assert.equal(plain.body.description, e.description);
});

test('description metadata round-trips and Los Angeles midnight converts with DST', () => {
  const d = composeDescription('Pay online.', 'CA-FTB', 'widgets');
  assert.equal(d, 'Pay online.\n\nBody: CA-FTB · Entity: widgets');
  assert.deepEqual(parseMeta(d), { notes: 'Pay online.', body: 'CA-FTB', entity: 'widgets' });
  assert.deepEqual(parseMeta('Entity: acme'), { notes: '', body: null, entity: 'acme' });
  assert.equal(parseMeta('free text').entity, null);
  assert.equal(zonedToUtc('2026-01-15'), '2026-01-15T08:00:00.000Z');
  assert.equal(zonedToUtc('2026-07-15'), '2026-07-15T07:00:00.000Z');
  assert.equal(reminderMinutes('28d'), 40320);
  assert.throws(() => reminderMinutes('29d'), /max 28d/);
  assert.throws(() => reminderMinutes('-1d'), /28d/);
});

test('deadlines calendars keep a stable uid via import; plain calendars insert without notifications', async (t) => {
  const fake = withFake(t);
  const { created } = await addEvent(account, {
    calendar: 'deadlines',
    title: 'File DE annual report',
    date: '2027-03-01',
    body: 'DE',
    recurrence: 'FREQ=YEARLY',
    notes: 'From acme inbox: "Annual report reminder"',
  });
  assert.equal(created.uid, 'acme-file-de-annual-report-2027@compliance');
  assert.equal(created.summary, 'ACME: File DE annual report');
  assert.equal(created.body, 'DE');
  assert.deepEqual(created.reminders, ['28d', '7d']);
  const post = fake.requests.find((r) => r.method === 'POST');
  assert.match(post.path, /\/events\/import$/);
  assert.equal(post.body.attendees, undefined);
  assert.equal(post.body.transparency, 'transparent');
  await assert.rejects(
    addEvent(account, {
      calendar: 'deadlines',
      title: 'File DE annual report',
      date: '2027-03-01',
    }),
    /already exists/,
  );

  const trip = await addEvent(account, {
    calendar: 'travel',
    title: 'Flight to NYC',
    date_time: '2027-05-01T08:15',
    end_date_time: '2027-05-01T16:40',
    location: 'SFO',
  });
  const insert = fake.requests.at(-1);
  assert.match(insert.path, /\/events$/);
  assert.equal(insert.params.sendUpdates, 'none');
  assert.deepEqual(insert.body.reminders, { useDefault: true });
  assert.equal(insert.body.attendees, undefined);
  assert.equal(trip.created.summary, 'Flight to NYC');
  assert.equal(trip.created.entity, undefined);

  await assert.rejects(
    addEvent(account, { calendar: 'travel', title: 'x', date: '2027-02-30' }),
    /YYYY-MM-DD/,
  );
  await assert.rejects(
    addEvent(account, {
      calendar: 'travel',
      title: 'x',
      date_time: '2027-05-01T10:00',
      end_date_time: '2027-05-01T09:00',
    }),
    /after date_time/,
  );
  await assert.rejects(
    addEvent(account, {
      calendar: 'deadlines',
      title: 'x',
      date: '2027-03-01',
      recurrence: 'FREQ=YEARLY\nATTENDEE:x',
    }),
    /RRULE/,
  );
});

test('update and delete send no notifications and refuse meetings and special event types', async (t) => {
  const fake = withFake(t, {
    [CAL]: [
      {
        iCalUID: 'u1@acme-compliance',
        id: 'ev9',
        summary: 'ACME: Old',
        description: 'Old notes\n\nBody: IRS · Entity: acme',
        start: { date: '2027-01-01' },
        end: { date: '2027-01-02' },
      },
      {
        iCalUID: 'meeting@google.com',
        id: 'ev10',
        summary: 'Standup',
        start: { date: '2027-01-01' },
        attendees: [{ email: 'x@example.test' }],
      },
      {
        iCalUID: 'ooo@google.com',
        id: 'ev11',
        summary: 'Out of office',
        eventType: 'outOfOffice',
        start: { dateTime: '2027-01-01T09:00:00' },
      },
    ],
  });
  const { updated } = await updateEvent(account, {
    calendar: 'deadlines',
    uid: 'u1@acme-compliance',
    date: '2027-01-05',
  });
  assert.equal(updated.dtstart, '2027-01-05');
  assert.equal(updated.body, 'IRS');
  assert.equal(updated.notes, 'Old notes');
  assert.equal(fake.requests.find((r) => r.method === 'PATCH').params.sendUpdates, 'none');
  for (const uid of ['meeting@google.com', 'ooo@google.com']) {
    await assert.rejects(
      updateEvent(account, { calendar: 'deadlines', uid, title: 'x' }),
      /instead/,
    );
    await assert.rejects(deleteEvent(account, { calendar: 'deadlines', uid }), /instead/);
  }
  const listed = await listEvents(account, { calendar: 'deadlines', from: '2027-01-01' });
  const meeting = listed.events.find((e) => e.uid === 'meeting@google.com');
  assert.equal(meeting.guests, 1);
  assert.equal(meeting.read_only, true);
  const { deleted } = await deleteEvent(account, {
    calendar: 'deadlines',
    uid: 'u1@acme-compliance',
  });
  assert.equal(deleted.summary, 'ACME: Old');
  assert.equal(fake.requests.at(-1).params.sendUpdates, 'none');
});

test('list expands a 90-day Los Angeles range by default; import is a dry run unless applied', async (t) => {
  const fake = withFake(t, {
    [CAL]: [
      {
        iCalUID: 'kept@acme-compliance',
        id: 'ev1',
        summary: 'ACME: Kept',
        start: { date: '2027-01-01' },
        end: { date: '2027-01-02' },
      },
    ],
  });
  const list = await listEvents(account, { calendar: 'deadlines', from: '2027-01-01' });
  assert.equal(list.to, '2027-04-01');
  const get = fake.requests.at(-1);
  assert.equal(get.params.singleEvents, 'true');
  assert.equal(get.params.timeMin, '2027-01-01T08:00:00.000Z');
  assert.equal(list.events[0].calendar, 'deadlines');

  const events = parseIcs(
    [
      'BEGIN:VEVENT',
      'UID:kept@acme-compliance',
      'DTSTART;VALUE=DATE:20270101',
      'SUMMARY:ACME: Kept',
      'END:VEVENT',
      'BEGIN:VEVENT',
      'UID:new@acme-compliance',
      'DTSTART;VALUE=DATE:20270201',
      'SUMMARY:ACME: New',
      'END:VEVENT',
    ].join('\n'),
  ).events;
  const dry = await importEvents(account, events, { calendar: 'deadlines' });
  assert.equal(dry.would_import, 1);
  assert.equal(dry.skipped_existing, 1);
  assert.equal(fake.calendars.get(CAL).has('new@acme-compliance'), false);
  const applied = await importEvents(account, events, { calendar: 'deadlines', apply: true });
  assert.equal(applied.imported, 1);
  await assert.rejects(importEvents(account, events, { calendar: 'main' }), /read-only/);
});

test('calendar login verifies the address, creates calendars once, then reuses them', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cal-oauth-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'client.json');
  fs.writeFileSync(
    file,
    JSON.stringify({
      installed: {
        client_id: 'example.apps.googleusercontent.com',
        client_secret: 'test-client-value',
        redirect_uris: ['http://localhost'],
      },
    }),
    { mode: 0o600 },
  );
  const profile = calendarProfile(/** @type {any} */ (account));
  let created = 0;
  let email = account.user;
  const fetchImpl = async (url, options = {}) => {
    if (url.includes('oauth2.googleapis.com/token'))
      return json({
        access_token: 'access',
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_token: 'refresh',
        scope: profile.scopes.join(' '),
      });
    if (url === USERINFO_URL) return json({ email, email_verified: true });
    if (url === `${CALENDAR_ROOT}calendars` && options.method === 'POST') {
      created++;
      return json({ id: `new${created}@group.calendar.google.com` });
    }
    if (url.startsWith(`${CALENDAR_ROOT}calendars/`)) return json({ items: [] });
    throw new Error(`unexpected ${url}`);
  };
  const saved = [];
  const options = {
    fetchImpl,
    flow: async () => ({ code: 'code', code_verifier: 'v', redirect_uri: 'http://127.0.0.1/cb' }),
    profile,
    manager: { invalidate() {} },
    read: async () => saved.at(-1)?.credential,
    write: async (id, credential, service) => saved.push({ id, credential, service }),
  };
  await authorize(/** @type {any} */ (account), file, /** @type {any} */ (options));
  assert.equal(saved[0].service, 'multi-mail-mcp.gcal-oauth');
  assert.deepEqual(Object.keys(saved[0].credential.calendar_ids), ['deadlines', 'travel']);
  assert.equal(created, 2);
  await authorize(/** @type {any} */ (account), file, /** @type {any} */ (options));
  assert.equal(created, 2, 'second login reuses both calendars');
  email = 'someone-else@example.test';
  await assert.rejects(
    authorize(/** @type {any} */ (account), file, /** @type {any} */ (options)),
    /does not match/,
  );
  assert.equal(saved.length, 2);
});

test('one server: calendar tools only with CAL_ACCOUNTS; bad calendar config fails at startup', async (t) => {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'multi-cal-test-')));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const config = path.join(dir, 'accounts.json');
  const registry = (calendars) => ({
    accounts: {
      acme: { type: 'gmail', user: 'ops@example.test', entity: 'acme', calendars },
      home: { type: 'gmail', user: 'me@example.test', entity: 'home' },
      widgets: { type: 'proton', user: 'w@example.test', entity: 'widgets' },
    },
  });
  fs.writeFileSync(config, JSON.stringify(registry(account.calendars)), { mode: 0o600 });
  const tools = async (env) => {
    const client = new Client({ name: 'calendar-test', version: '1.0.0' });
    await client.connect(
      new StdioClientTransport({
        command: process.execPath,
        args: [path.join(repo, 'index.js')],
        env: { PATH: process.env.PATH, MAIL_MCP_CONFIG: config, ...env },
        stderr: 'pipe',
      }),
    );
    const names = (await client.listTools()).tools.map((x) => x.name);
    return { client, names };
  };
  const cal = await tools({ CAL_ACCOUNTS: '*' });
  t.after(() => cal.client.close());
  assert.ok(cal.names.includes('cal__add_event'));
  assert.ok(!cal.names.some((n) => n.startsWith('mail__')));
  // "*" allows only accounts with calendars configured: here just acme.
  const listed = await cal.client.callTool({ name: 'cal__get_event', arguments: { uid: 'x@y' } });
  assert.doesNotMatch(JSON.parse(listed.content[0].text).error, /Name an account/);
  const denied = await cal.client.callTool({
    name: 'cal__get_event',
    arguments: { account: 'home', uid: 'x@compliance' },
  });
  assert.match(JSON.parse(denied.content[0].text).error, /not available here/);

  const mail = await tools({ MAIL_ACCOUNTS: 'acme' });
  t.after(() => mail.client.close());
  assert.ok(mail.names.includes('mail__search'));
  assert.ok(!mail.names.some((n) => n.startsWith('cal__')));

  const startup = (calendars, env = { CAL_ACCOUNTS: 'acme' }) => {
    fs.writeFileSync(config, JSON.stringify(registry(calendars)));
    return spawnSync(process.execPath, [path.join(repo, 'index.js'), '--check'], {
      env: { PATH: process.env.PATH, MAIL_MCP_CONFIG: config, ...env },
      encoding: 'utf8',
      timeout: 10000,
    });
  };
  for (const [calendars, message] of [
    [{ x: { create: 'X', id: 'primary', access: 'read' } }, /exactly one/],
    [{ x: { id: 'primary', access: 'admin' } }, /"access"/],
    [{ x: { id: 'https://evil.example/', access: 'read' } }, /"id"/],
    [{ '*': { access: 'write', kind: 'deadlines' } }, /unknown key/],
    [{}, /non-empty/],
  ]) {
    const result = startup(calendars);
    assert.equal(result.status, 1);
    assert.match(result.stderr, message);
  }
  const noCalendars = startup(account.calendars, { CAL_ACCOUNTS: 'home' });
  assert.match(noCalendars.stderr, /no "calendars" configured/);
});
