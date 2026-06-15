const { Client } = require('pg')
const crypto = require('crypto')

const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000

const LUNCH_ALLOWED = new Set([
  'andrea.volponi@intellisync.it',
  'biagio.dimicco@baxenergy.com',
  'roberto.tundo@baxenergy.com',
  'dante.cafarelli@baxenergy.com',
  'sara.cerreto@baxenergy.com',
  'giorgia.ciancio@baxenergy.com',
  'kok.see-mun@yokogawa.com',
  'ivan.dilelio@baxenergy.com',
  'yukio.hirota@yokogawa.com',
  'nwe-ni.swe@yokogawa.com',
  'takeshi.s@yokogawa.com',
  'shin.kakuya@yokogawa.com',
  'simone.debellis@baxenergy.com',
])

const NAME_MAP = {
  'andrea.volponi@intellisync.it': 'Andrea Volponi',
  'biagio.dimicco@baxenergy.com': 'Biagio Di Micco',
  'roberto.tundo@baxenergy.com': 'Roberto Tundo',
  'dante.cafarelli@baxenergy.com': 'Dante Cafarelli',
  'sara.cerreto@baxenergy.com': 'Sara Cerreto',
  'giorgia.ciancio@baxenergy.com': 'Giorgia Ciancio',
  'kok.see-mun@yokogawa.com': 'See-Mun Kok',
  'ivan.dilelio@baxenergy.com': 'Ivan Di Lelio',
  'yukio.hirota@yokogawa.com': 'Yukio Hirota',
  'nwe-ni.swe@yokogawa.com': 'Nwe-Ni Swe',
  'takeshi.s@yokogawa.com': 'Takeshi Suzuki',
  'shin.kakuya@yokogawa.com': 'Shin Kakuya',
  'simone.debellis@baxenergy.com': 'Simone De Bellis',
}

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

const CREATE_TABLE = `
  CREATE TABLE IF NOT EXISTS lunch_orders (
    email TEXT PRIMARY KEY,
    name TEXT,
    first_course TEXT,
    main_course TEXT,
    side_dishes TEXT,
    dessert TEXT,
    notes TEXT,
    submitted_at TIMESTAMPTZ DEFAULT NOW()
  )
`

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') { res.status(405).end(); return }

  const secret = process.env.AUTH_SECRET
  if (!secret) { res.status(500).json({ error: 'server_error' }); return }

  const email = getEmailFromCookie(req.headers.cookie || '', secret)
  if (!email) { res.status(401).json({ error: 'unauthenticated' }); return }
  if (!LUNCH_ALLOWED.has(email)) { res.status(403).json({ error: 'forbidden' }); return }

  const body = req.body || {}
  const name = NAME_MAP[email] || email
  const sideDishesList = Array.isArray(body.contorni) ? body.contorni.join(', ') : (body.contorni || null)

  const client = new Client({ ...DB_CONFIG, password: process.env.SUPABASE_DB_PASSWORD })
  try {
    await client.connect()
    await client.query(CREATE_TABLE)
    await client.query(
      `INSERT INTO lunch_orders (email, name, first_course, main_course, side_dishes, dessert, notes, submitted_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
       ON CONFLICT (email) DO UPDATE SET
         name = EXCLUDED.name,
         first_course = EXCLUDED.first_course,
         main_course = EXCLUDED.main_course,
         side_dishes = EXCLUDED.side_dishes,
         dessert = EXCLUDED.dessert,
         notes = EXCLUDED.notes,
         submitted_at = NOW()`,
      [email, name, body.primo || null, body.secondo || null, sideDishesList, body.dolce || null, body.note || null]
    )
    res.status(200).json({ ok: true })
  } catch (err) {
    console.error('lunch order error:', err.message)
    res.status(500).json({ error: 'db_error' })
  } finally {
    await client.end().catch(() => {})
  }
}
