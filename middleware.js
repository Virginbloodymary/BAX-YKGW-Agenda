const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000

function getCookieValue(header, name) {
  if (!header) return null
  for (const part of header.split(';')) {
    const eq = part.indexOf('=')
    if (eq < 0) continue
    const k = part.slice(0, eq).trim()
    if (k === name) return part.slice(eq + 1).trim()
  }
  return null
}

function hexToBytes(hex) {
  const arr = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    arr[i / 2] = parseInt(hex.slice(i, i + 2), 16)
  }
  return arr
}

async function verifyToken(raw, secret) {
  try {
    const decoded = decodeURIComponent(raw)
    // format: email:timestamp:hmac  (email has no colon)
    const lastColon = decoded.lastIndexOf(':')
    if (lastColon < 0) return false
    const sig = decoded.slice(lastColon + 1)
    const payload = decoded.slice(0, lastColon)

    const secondLastColon = payload.lastIndexOf(':')
    if (secondLastColon < 0) return false
    const ts = parseInt(payload.slice(secondLastColon + 1), 10)
    if (isNaN(ts) || Date.now() - ts > THIRTY_DAYS_MS) return false

    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    )
    return await crypto.subtle.verify(
      'HMAC',
      key,
      hexToBytes(sig),
      new TextEncoder().encode(payload)
    )
  } catch {
    return false
  }
}

export default async function middleware(request) {
  const url = new URL(request.url)
  const path = url.pathname

  if (path === '/login.html' || path.startsWith('/api/')) return

  const secret = process.env.AUTH_SECRET
  const raw = getCookieValue(request.headers.get('cookie'), 'bax_auth')

  if (!secret || !raw || !(await verifyToken(raw, secret))) {
    return Response.redirect(new URL('/login.html', request.url), 302)
  }
}

export const config = {
  matcher: ['/:path*'],
}
