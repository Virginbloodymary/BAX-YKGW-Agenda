const crypto = require('crypto')

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

module.exports = function handler(req, res) {
  const secret = process.env.AUTH_SECRET
  if (!secret) {
    res.status(500).json({ error: 'server_error' })
    return
  }

  const raw = getCookieValue(req.headers.cookie || '', 'bax_auth')
  if (!raw) {
    res.status(401).json({ error: 'unauthenticated' })
    return
  }

  try {
    const decoded = decodeURIComponent(raw)
    const lastColon = decoded.lastIndexOf(':')
    if (lastColon < 0) throw new Error()
    const sig = decoded.slice(lastColon + 1)
    const payload = decoded.slice(0, lastColon)

    const secondLastColon = payload.lastIndexOf(':')
    if (secondLastColon < 0) throw new Error()
    const ts = parseInt(payload.slice(secondLastColon + 1), 10)
    if (isNaN(ts) || Date.now() - ts > THIRTY_DAYS_MS) throw new Error()

    const email = payload.slice(0, secondLastColon)
    const expectedSig = crypto.createHmac('sha256', secret).update(payload).digest('hex')
    if (sig !== expectedSig) throw new Error()

    res.setHeader('Cache-Control', 'no-store')
    res.status(200).json({ email })
  } catch {
    res.status(401).json({ error: 'unauthenticated' })
  }
}
