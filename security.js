// Bidi overrides/isolates (extension spoofing: "invoice‮fdp.exe"), zero-width and
// Unicode tag characters, and C0/C1 controls.
export const HIDDEN_CHARS = /[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁠-⁩﻿]|[\u{E0000}-\u{E007F}]/gu;

/** Remove invisible/control characters a message could use to hide text from a human reviewer. */
export function stripHidden(text) {
  let n = 0;
  const out = text.replace(HIDDEN_CHARS, (c) => (c === '\n' || c === '\t' || c === '\r' ? c : (n++, '')));
  return { text: out, removed: n };
}

/** Reject calendar dates that JavaScript would silently normalize, such as February 30. */
export function isCalendarDate(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value;
}

/** Server errors may contain sender-controlled text too. Never return an object dump. */
export function publicError(error) {
  const message = typeof error?.message === 'string' ? error.message : 'Operation failed';
  return stripHidden(message).text.slice(0, 500);
}

/** Bound the result returned to the assistant, including headers and attachment metadata. */
export function serializeResult(payload) {
  const text = JSON.stringify(payload, null, 2);
  // Includes room for the base64 encoding of the 2 MB inline attachment allowance.
  if (Buffer.byteLength(text, 'utf8') > 3 * 1024 * 1024) {
    throw new Error('Result exceeds 3 MB; reduce limit, max_chars or attachment indexes');
  }
  return text;
}
