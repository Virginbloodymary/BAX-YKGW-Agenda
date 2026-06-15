const { Client } = require('pg')
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

function getEmailFromCookie(cookieHeader, secret) {
  try {
    const raw = getCookieValue(cookieHeader, 'bax_auth')
    if (!raw) return null
    const decoded = decodeURIComponent(raw)
    const lastColon = decoded.lastIndexOf(':')
    if (lastColon < 0) return null
    const sig = decoded.slice(lastColon + 1)
    const payload = decoded.slice(0, lastColon)
    const secondLastColon = payload.lastIndexOf(':')
    if (secondLastColon < 0) return null
    const ts = parseInt(payload.slice(secondLastColon + 1), 10)
    if (isNaN(ts) || Date.now() - ts > THIRTY_DAYS_MS) return null
    const email = payload.slice(0, secondLastColon)
    const expectedSig = crypto.createHmac('sha256', secret).update(payload).digest('hex')
    if (sig !== expectedSig) return null
    return email
  } catch {
    return null
  }
}

const DB_CONFIG = {
  host: 'aws-1-eu-central-1.pooler.supabase.com',
  port: 6543,
  database: 'postgres',
  user: 'postgres.uyptxrvmdmvrircmqoqu',
  ssl: { rejectUnauthorized: false },
}

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') { res.status(405).end(); return }

  const secret = process.env.AUTH_SECRET
  if (!secret) { res.status(500).json({ error: 'server_error' }); return }

  const email = getEmailFromCookie(req.headers.cookie || '', secret)
  if (!email) { res.status(401).json({ error: 'unauthenticated' }); return }
  if (email !== 'sara.cerreto@baxenergy.com') { res.status(403).json({ error: 'forbidden' }); return }

  const client = new Client({ ...DB_CONFIG, password: process.env.SUPABASE_DB_PASSWORD })
  try {
    await client.connect()
    const result = await client.query(
      `SELECT name, email, first_course, main_course, side_dishes, dessert, notes, submitted_at
       FROM lunch_orders
       ORDER BY submitted_at ASC`
    )
    res.setHeader('Cache-Control', 'no-store')
    res.status(200).json({ orders: result.rows })
  } catch (err) {
    console.error('orders fetch error:', err.message)
    res.status(500).json({ error: 'db_error' })
  } finally {
    await client.end().catch(() => {})
  }
}
