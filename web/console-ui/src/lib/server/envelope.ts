/**
 * The gateway answer envelope, unwrapped.
 *
 * The gateway answers `{code, status, message, data}`, and a list answer adds
 * `meta` with the page, the limit, the total, and the total pages. Every console
 * reader wants the payload, so the unwrapping happens once, here, and both the
 * BFF route and the server-side reads use it.
 */

/**
 * Returns the payload of one parsed envelope. A value that carries no `data` key
 * is not an envelope, and it comes back as it stands.
 *
 * `meta` is merged onto the payload as the browser's `Page<T>`: an array payload
 * becomes its `items`, and an object payload keeps its own fields. Dropping
 * `meta` would leave the pager with rows and no page numbers.
 */
function payloadOf(parsed: unknown): unknown {
  if (!parsed || typeof parsed !== "object" || !("data" in parsed)) return parsed

  const { data, meta } = parsed as { data: unknown; meta?: Record<string, unknown> }
  if (!meta) return data
  return Array.isArray(data) || data === null ? { items: data ?? [], ...meta } : { ...data, ...meta }
}

/**
 * Returns the payload of one envelope, parsed. A server-side reader wants the
 * value, so it takes this one and never stringifies what it is about to parse.
 *
 * A body that is not JSON throws, the same way `JSON.parse` throws. Every caller
 * reads inside a `try` already, because a failed read is a state the shell
 * renders.
 */
export function unwrapJSON<T>(body: string): T {
  return payloadOf(JSON.parse(body)) as T
}

/**
 * Returns the payload of the envelope, as a string. The BFF route relays a body
 * onward, so it takes this one.
 *
 * A body that is empty, that is not JSON, or that carries no `data` key comes
 * back unchanged, so a non-envelope answer from a proxy still reaches the caller
 * intact.
 */
export function unwrap(body: string): string {
  if (!body) return body
  try {
    const parsed: unknown = JSON.parse(body)
    if (!parsed || typeof parsed !== "object" || !("data" in parsed)) return body
    return JSON.stringify(payloadOf(parsed))
  } catch {
    return body
  }
}
