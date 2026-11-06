// Per-process bounds: reject excess work rather than queuing unbounded mailbox reads.
const MAX_ACTIVE_OPERATIONS = 2;
let active = 0;

/**
 * @template T
 * @param {() => Promise<T>} fn
 * @returns {Promise<T>}
 */
export async function withOperationSlot(fn) {
  if (active >= MAX_ACTIVE_OPERATIONS)
    throw new Error('Mail server busy; retry after an active operation finishes');
  active++;
  try {
    return await fn();
  } finally {
    active--;
  }
}

/** A server that never answers LOGOUT must not keep a completed tool call pending. */
export async function logoutBounded(client, timeoutMs = 5000) {
  let timer;
  try {
    await Promise.race([
      Promise.resolve().then(() => client.logout()),
      new Promise((resolve) => {
        timer = setTimeout(resolve, timeoutMs);
      }),
    ]);
  } catch {
    // Closing below is also the fallback when LOGOUT rejects.
  } finally {
    clearTimeout(timer);
    client.close();
  }
}
