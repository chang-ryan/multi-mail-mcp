import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import {
  addDeadline,
  CALENDAR,
  composeDescription,
  configureCalendar,
  deleteDeadline,
  importDeadlines,
  listDeadlines,
  parseMeta,
  planImport,
  reminderMinutes,
  updateDeadline,
  zonedToUtc,
} from '../calendar-core.js';
import { CALENDAR_ROOT, googleJson, USERINFO_URL } from '../google-http.js';
import { parseIcs, triggerMinutes } from '../ics.js';
import { authorize, validateScope } from '../oauth.js';

const repo = fileURLToPath(new URL('../', import.meta.url));
const account = { id: 'acme', type: 'gmail', user: 'ops@example.test', entity: 'acme' };
const CAL = 'abc123@group.calendar.google.com';
const json = (value, status = 200) => new Response(JSON.stringify(value), { status });

/** Fake Calendar API: records requests and keeps events by iCalUID. */
function fakeCalendar(initial = []) {
  const events = new Map(initial.map((e) => [e.iCalUID, e]));
  const requests = [];
  let next = 1;
  const fetchImpl = async (url, options = {}) => {
    const u = new URL(url);
    const method = options.method || 'GET';
    const body = options.body ? JSON.parse(options.body) : undefined;
    requests.push({ method, path: u.pathname, params: Object.fromEntries(u.searchParams), body });
    assert.equal(options.headers.Authorization, 'Bearer access');
    const base = `/calendar/v3/calendars/${encodeURIComponent(CAL)}`;
    if (method === 'GET' && u.pathname === `${base}/events`) {
      const uid = u.searchParams.get('iCalUID');
      return json({ items: uid ? [events.get(uid)].filter(Boolean) : [...events.values()] });
    }
    if (method === 'POST' && u.pathname === `${base}/events/import`) {
      const created = { ...body, id: `ev${next++}` };
      events.set(body.iCalUID, created);
      return json(created);
    }
    const id = u.pathname.slice(`${base}/events/`.length);
    const found = [...events.values()].find((e) => e.id === id);
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
    metadata: () => ({ calendar_id: CAL }),
  };
  return { events, requests, fetchImpl, tokens };
}

function withFake(t, initial) {
  const fake = fakeCalendar(initial);
  configureCalendar({ fetchImpl: fake.fetchImpl, tokens: /** @type {any} */ (fake.tokens) });
  t.after(() => configureCalendar());
  return fake;
}

test('calendar grant is exactly openid, email and calendar.app.created', () => {
  validateScope(
    'https://www.googleapis.com/auth/calendar.app.created openid https://www.googleapis.com/auth/userinfo.email',
    CALENDAR,
  );
  validateScope(`openid email ${'https://www.googleapis.com/auth/calendar.app.created'}`, CALENDAR);
  for (const bad of [
    'openid email',
    'openid email https://www.googleapis.com/auth/calendar',
    'openid email https://www.googleapis.com/auth/calendar.app.created https://www.googleapis.com/auth/gmail.readonly',
    'openid openid https://www.googleapis.com/auth/calendar.app.created',
  ])
    assert.throws(() => validateScope(bad, CALENDAR), /calendar.app.created/);
  // A calendar grant never passes as a Gmail grant, and vice versa.
  assert.throws(() => validateScope('openid email', undefined), /gmail.readonly/);
});

test('only app-created calendars and the deadline methods are reachable', async () => {
  const ok = async () => json({});
  const cal = `${CALENDAR_ROOT}calendars/${encodeURIComponent(CAL)}`;
  for (const [url, method] of [
    [`${CALENDAR_ROOT}calendars`, 'POST'],
    [cal, 'GET'],
    [`${cal}/events`, 'GET'],
    [`${cal}/events/import`, 'POST'],
    [`${cal}/events/ev1`, 'PATCH'],
    [`${cal}/events/ev1`, 'DELETE'],
    [USERINFO_URL, 'GET'],
  ])
    await googleJson(url, { method }, { fetchImpl: ok });
  for (const [url, method] of [
    [`${CALENDAR_ROOT}calendars/primary/events`, 'GET'],
    [`${CALENDAR_ROOT}calendars/${encodeURIComponent('someone@gmail.com')}/events`, 'GET'],
    [`${cal}/events`, 'POST'], // insert would replace the iCalUID; import is used instead
    [`${cal}`, 'DELETE'],
    [`${cal}/acl`, 'POST'],
    [`${CALENDAR_ROOT}users/me/calendarList`, 'GET'],
    [`${cal}/events/ev1/move`, 'POST'],
    [USERINFO_URL, 'POST'],
  ])
    await assert.rejects(googleJson(url, { method }, { fetchImpl: ok }), /refused/);
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

test('add keeps the uid via import, prefixes the title, and never carries guests', async (t) => {
  const fake = withFake(t);
  const { created } = await addDeadline(account, {
    title: 'File DE annual report',
    date: '2027-03-01',
    body: 'DE',
    recurrence: 'FREQ=YEARLY',
    notes: 'From acme inbox: "Annual report reminder"',
  });
  assert.equal(created.uid, 'acme-file-de-annual-report-2027@compliance');
  assert.equal(created.summary, 'ACME: File DE annual report');
  assert.equal(created.rrule, 'FREQ=YEARLY');
  assert.equal(created.body, 'DE');
  assert.deepEqual(created.reminders, ['28d', '7d']);
  const post = fake.requests.find((r) => r.method === 'POST');
  assert.match(post.path, /\/events\/import$/);
  assert.equal(post.body.attendees, undefined);
  assert.equal(post.body.transparency, 'transparent');
  assert.equal(post.body.end.date, '2027-03-02');
  assert.equal(post.body.extendedProperties.private.obligation_id, created.uid);
  await assert.rejects(
    addDeadline(account, { title: 'File DE annual report', date: '2027-03-01' }),
    /already exists/,
  );
  await assert.rejects(addDeadline(account, { title: 'x', date: '2027-02-30' }), /YYYY-MM-DD/);
  await assert.rejects(
    addDeadline(account, {
      title: 'x',
      date: '2027-03-01',
      reminders: ['1d', '2d', '3d', '4d', '5d', '6d'],
    }),
    /At most 5/,
  );
  await assert.rejects(
    addDeadline(account, { title: 'x', date: '2027-03-01', recurrence: 'FREQ=YEARLY\nATTENDEE:x' }),
    /RRULE/,
  );
});

test('update patches without notifications, keeps metadata, and refuses events with guests', async (t) => {
  const fake = withFake(t, [
    {
      iCalUID: 'u1@acme-compliance',
      id: 'ev9',
      summary: 'ACME: Old',
      description: 'Old notes\n\nBody: IRS · Entity: acme',
      start: { date: '2027-01-01' },
      end: { date: '2027-01-02' },
    },
    {
      iCalUID: 'guest@acme-compliance',
      id: 'ev10',
      summary: 'ACME: Meeting',
      start: { date: '2027-01-01' },
      attendees: [{ email: 'x@example.test' }],
    },
  ]);
  const { updated } = await updateDeadline(account, {
    uid: 'u1@acme-compliance',
    date: '2027-01-05',
  });
  assert.equal(updated.dtstart, '2027-01-05');
  assert.equal(updated.body, 'IRS');
  assert.equal(updated.notes, 'Old notes');
  const patch = fake.requests.find((r) => r.method === 'PATCH');
  assert.equal(patch.params.sendUpdates, 'none');
  await assert.rejects(
    updateDeadline(account, { uid: 'guest@acme-compliance', title: 'x' }),
    /has guests/,
  );
  await assert.rejects(updateDeadline(account, { uid: 'missing@x', title: 'x' }), /No deadline/);
  const { deleted } = await deleteDeadline(account, { uid: 'u1@acme-compliance' });
  assert.equal(deleted.summary, 'ACME: Old');
  assert.equal(fake.requests.at(-1).params.sendUpdates, 'none');
  assert.equal(fake.events.has('u1@acme-compliance'), false);
});

test('list expands a 90-day Los Angeles range by default; import is a dry run unless applied', async (t) => {
  const fake = withFake(t, [
    {
      iCalUID: 'kept@acme-compliance',
      id: 'ev1',
      summary: 'ACME: Kept',
      start: { date: '2027-01-01' },
      end: { date: '2027-01-02' },
    },
  ]);
  const list = await listDeadlines(account, { from: '2027-01-01' });
  assert.equal(list.to, '2027-04-01');
  const get = fake.requests.at(-1);
  assert.equal(get.params.singleEvents, 'true');
  assert.equal(get.params.timeMin, '2027-01-01T08:00:00.000Z');
  assert.equal(list.deadlines[0].uid, 'kept@acme-compliance');

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
  const dry = await importDeadlines(account, events);
  assert.equal(dry.would_import, 1);
  assert.equal(dry.skipped_existing, 1);
  assert.equal(fake.events.has('new@acme-compliance'), false);
  const applied = await importDeadlines(account, events, { apply: true });
  assert.equal(applied.imported, 1);
  assert.equal(fake.events.get('new@acme-compliance').iCalUID, 'new@acme-compliance');
});

test('calendar login verifies the address, creates the Deadlines calendar once, then reuses it', async (t) => {
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
  const scope = `openid https://www.googleapis.com/auth/userinfo.email ${'https://www.googleapis.com/auth/calendar.app.created'}`;
  let created = 0;
  let email = account.user;
  const fetchImpl = async (url, options = {}) => {
    if (url.includes('oauth2.googleapis.com/token'))
      return json({
        access_token: 'access',
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_token: 'refresh',
        scope,
      });
    if (url === USERINFO_URL) return json({ email, email_verified: true });
    if (url === `${CALENDAR_ROOT}calendars` && options.method === 'POST') {
      created++;
      assert.match(JSON.parse(options.body).summary, /^Deadlines \[ACME\]$/);
      return json({ id: CAL, summary: 'Deadlines [ACME]' });
    }
    if (url === `${CALENDAR_ROOT}calendars/${encodeURIComponent(CAL)}`)
      return json({ id: CAL, summary: 'Deadlines [ACME]' });
    throw new Error(`unexpected ${url}`);
  };
  const saved = [];
  const store = {
    read: async () => saved.at(-1)?.credential,
    write: async (id, credential, service) => saved.push({ id, credential, service }),
  };
  const options = {
    fetchImpl,
    flow: async () => ({ code: 'code', code_verifier: 'v', redirect_uri: 'http://127.0.0.1/cb' }),
    profile: CALENDAR,
    manager: { invalidate() {} },
    ...store,
  };
  const log = console.log;
  console.log = () => {};
  t.after(() => {
    console.log = log;
  });
  await authorize(/** @type {any} */ (account), file, /** @type {any} */ (options));
  assert.equal(saved[0].service, 'multi-mail-mcp.gcal-oauth');
  assert.equal(saved[0].credential.calendar_id, CAL);
  await authorize(/** @type {any} */ (account), file, /** @type {any} */ (options));
  assert.equal(created, 1);
  email = 'someone-else@example.test';
  await assert.rejects(
    authorize(/** @type {any} */ (account), file, /** @type {any} */ (options)),
    /does not match/,
  );
  assert.equal(saved.length, 2);
});

test('one server: calendar tools only with CAL_ACCOUNTS, mail tools only with MAIL_ACCOUNTS', async (t) => {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'multi-cal-test-')));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const config = path.join(dir, 'accounts.json');
  fs.writeFileSync(
    config,
    JSON.stringify({
      accounts: {
        acme: { type: 'gmail', user: 'ops@example.test', entity: 'acme' },
        personal: { type: 'gmail', user: 'me@example.test', entity: 'home' },
        widgets: { type: 'proton', user: 'widgets@example.test', entity: 'widgets' },
      },
    }),
    { mode: 0o600 },
  );
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
  assert.ok(cal.names.includes('cal__add_deadline'));
  assert.ok(!cal.names.some((n) => n.startsWith('mail__')));
  const listed = await cal.client.callTool({ name: 'cal__list_accounts', arguments: {} });
  assert.deepEqual(
    JSON.parse(listed.content[0].text).accounts.map((a) => `${a.id}:${a.entity}`),
    ['acme:acme', 'personal:home'],
  );
  // Several accounts allowed: a change must name one.
  const ambiguous = await cal.client.callTool({
    name: 'cal__delete_deadline',
    arguments: { uid: 'x@compliance' },
  });
  assert.equal(ambiguous.isError, true);
  assert.match(JSON.parse(ambiguous.content[0].text).error, /Name an account/);
  const denied = await cal.client.callTool({
    name: 'cal__get_deadline',
    arguments: { account: 'widgets', uid: 'x@compliance' },
  });
  assert.match(JSON.parse(denied.content[0].text).error, /not available here/);

  const mail = await tools({ MAIL_ACCOUNTS: 'acme' });
  t.after(() => mail.client.close());
  assert.ok(mail.names.includes('mail__search'));
  assert.ok(!mail.names.some((n) => n.startsWith('cal__')));
});
