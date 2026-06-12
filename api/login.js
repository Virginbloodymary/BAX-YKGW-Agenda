const crypto = require('crypto')

const ALLOWED = new Set([
  'giuseppe.falzone@baxenergy.com',
  'lodi@baxenergy.com',
  'losardo@baxenergy.com',
  'vecchiod@baxenergy.com',
  'barberam@baxenergy.com',
  'andrea.volponi@intellisync.it',
  'digiunta@baxenergy.com',
  'lazzaro@baxenergy.com',
  'federica.cutuli@baxenergy.com',
  'biagio.dimicco@baxenergy.com',
  'yanko.chamov@baxenergy.com',
  'laura.basile@baxenergy.com',
  'roberto.tundo@baxenergy.com',
  'dante.cafarelli@baxenergy.com',
  'sara.cerreto@baxenergy.com',
  'giorgia.ciancio@baxenergy.com',
  'kok.see-mun@yokogawa.com',
  'ivan.dilelio@baxenergy.com',
  'andrea.agostino@baxenergy.com',
  'yukio.hirota@yokogawa.com',
  'nwe-ni.swe@yokogawa.com',
  'lamalfa@baxenergy.com',
  'takeshi.s@yokogawa.com',
  'shin.kakuya@yokogawa.com',
  'didio@baxenergy.com',
  'orofino@baxenergy.com',
])

module.exports = function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).end()
    return
  }

  const secret = process.env.AUTH_SECRET
  if (!secret) {
    res.status(500).send('AUTH_SECRET not configured')
    return
  }

  const rawEmail =
    (req.body && typeof req.body === 'object' ? req.body.email : null) ||
    (typeof req.body === 'string' ? new URLSearchParams(req.body).get('email') : null) ||
    ''
  const email = rawEmail.toLowerCase().trim()

  if (!ALLOWED.has(email)) {
    res.redirect(302, '/login.html?error=1')
    return
  }

  const ts = Date.now()
  const payload = `${email}:${ts}`
  const sig = crypto.createHmac('sha256', secret).update(payload).digest('hex')
  const cookieVal = encodeURIComponent(`${payload}:${sig}`)

  res.setHeader(
    'Set-Cookie',
    `bax_auth=${cookieVal}; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax`
  )
  res.redirect(302, '/')
}
