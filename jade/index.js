/**
 * jade-demo — intentionally vulnerable Express app for SentinelAI demos.
 *
 * DO NOT DEPLOY. Every credential below is fabricated; every endpoint
 * contains at least one well-known vulnerability so scanners (secret,
 * SAST, DAST) have something to find and the AI fix engine has something
 * to patch.
 *
 * Demo coverage:
 *   1. Hardcoded credentials       — secret scanner
 *   2. SQL injection               — SAST (string-concat query)
 *   3. NoSQL injection             — SAST (unsanitised $where)
 *   4. Command injection           — SAST (child_process.exec with input)
 *   5. Path traversal              — SAST (fs.readFile from query string)
 *   6. eval() RCE                  — SAST (eval of request body)
 *   7. Weak crypto                 — SAST (md5 password hashing)
 *   8. Insecure deserialization    — SAST (JSON parse + assign to global)
 *   9. Hardcoded auth bypass       — logic flaw (admin shortcut)
 *  10. Verbose error leakage       — DAST (stack trace returned to client)
 */

const express        = require('express')
const mysql          = require('mysql2')
const { MongoClient } = require('mongodb')
const fs             = require('fs')
const path           = require('path')
const crypto         = require('crypto')
const { exec }       = require('child_process')
const jwt            = require('jsonwebtoken')

const csurf = require('csurf')
const app = express()
app.use(express.json())

// ─── Hardcoded credentials (secret scanner targets) ──────────────────────────

// GitHub PAT — FAKE prefix slips past GH push protection's verifier
const GITHUB_PAT      = 'ghp_FAKE16C7e42F292c6912E7710c838347Ae178B4a01D2'

// Generic 32-char hex API key (Datadog-style)
const DATADOG_API_KEY = '8f3c4d2e9a1b6f5e0c7d8a4b3e2f1d9c'

// Mailgun (legacy "key-" prefix)
const MAILGUN_API_KEY = 'key-1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p'

// SendGrid
const SENDGRID_API_KEY = 'SG.abcdefghijklmnopqrstuv.1234567890abcdefghijklmnopqrstuvwxyz1234567'

// Postgres connection URL with embedded password
const DATABASE_URL = 'postgresql://admin:S3cr3tP%40ssw0rd@db.internal.example.com:5432/production'

// MongoDB Atlas-style URL with creds
const MONGO_URL = 'mongodb+srv://root:mongoR00tPwd@cluster0.mongodb.net/?retryWrites=true'

// JWT signing key — never rotate, never revoke
const JWT_SECRET = 'jade-demo-not-so-secret-jwt-signing-key-2026'

// Weak symmetric key (32 bytes — looks ok but is hardcoded + reused)
const ENCRYPTION_KEY = '0123456789abcdef0123456789abcdef'

// MySQL connection — credentials baked into the source
const db = mysql.createConnection({
  host:     'db.internal.example.com',
  user:     'root',
  password: 'r00tDBp4ss!',
  database: 'jade',
})

const mongo = new MongoClient(MONGO_URL)


// ─── Vulnerable endpoints ────────────────────────────────────────────────────

/**
 * 1. SQL INJECTION
 *    Concatenates `req.query.username` directly into a SQL string.
 *    Trivial bypass: ?username=' OR '1'='1
 *    Fix: parameterised query — db.query('SELECT ... WHERE username = ?', [username])
 */
app.get('/users', (req, res) => {
  const username = req.query.username
  const sql = "SELECT id, email, role FROM users WHERE username = '" + username + "'"
  db.query(sql, (err, rows) => {
    if (err) return res.status(500).send(err.stack) // also leaks stack — see #10
    res.json(rows)
  })
})


/**
 * 2. NoSQL INJECTION
 *    Passes user-controlled JSON straight into a Mongo query operator.
 *    POST /search { "filter": { "$where": "this.role === 'admin'" } }
 *    Fix: validate filter shape, never accept $where, use a whitelist of fields.
 */
app.post('/search', async (req, res) => {
  const filter = req.body.filter || {}
  const docs = await mongo.db('jade').collection('users').find(filter).toArray()
  res.json(docs)
})


/**
 * 3. COMMAND INJECTION
 *    Builds a shell command from query params with no escaping.
 *    GET /ping?host=8.8.8.8;rm -rf /tmp
 *    Fix: use child_process.execFile with an args array, validate host as IP/FQDN.
 */
app.get('/ping', (req, res) => {
  const host = req.query.host
  exec(`ping -c 1 ${host}`, (err, stdout, stderr) => {
    if (err) return res.status(500).send(stderr)
    res.send(stdout)
  })
})


/**
 * 4. PATH TRAVERSAL
 *    Reads any file the request asks for.
 *    GET /files?name=../../../../etc/passwd
 *    Fix: path.resolve + verify the result starts with the allowed base dir.
 */
app.get('/files', (req, res) => {
  const fileName = req.query.name
  const filePath = path.join('/var/data/uploads', fileName)
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) return res.status(404).send('not found')
    res.send(data)
  })
})


/**
 * 5. eval() RCE
 *    Executes arbitrary JS submitted in the request body.
 *    POST /calc { "expr": "process.exit(1)" }
 *    Fix: never eval untrusted input — use a real expression parser like mathjs.
 */
app.post('/calc', (req, res) => {
  const expr = req.body.expr || '0'
  // eslint-disable-next-line no-eval
  const result = eval(expr)
  res.json({ result })
})


/**
 * 6. WEAK CRYPTO — md5 password hashing, no salt
 *    Fix: bcrypt or argon2 with per-user salt and a tuned cost factor.
 */
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex')
}

app.post('/register', (req, res) => {
  const { username, password } = req.body
  const hash = hashPassword(password)
  db.query(
    "INSERT INTO users (username, password_hash) VALUES ('" + username + "', '" + hash + "')",
    (err) => {
      if (err) return res.status(500).send(err.message)
      res.json({ ok: true })
    }
  )
})


/**
 * 7. INSECURE DESERIALIZATION — JSON.parse → Object.assign(global, ...)
 *    A request that posts {"process": {"env": {"PATH": ""}}} can poison globals.
 *    Fix: never merge untrusted input into a privileged object.
 */
app.post('/import', (req, res) => {
  const raw = req.body.config
  const parsed = JSON.parse(raw)
  Object.assign(global, parsed)   // prototype-pollution + global poisoning
  res.json({ imported: Object.keys(parsed) })
})


/**
 * 8. HARDCODED AUTH BYPASS — admin role short-circuits all checks
 *    Fix: remove the literal username check; always run the real auth flow.
 */
function authMiddleware(req, res, next) {
  const user = req.headers['x-user'] || ''

  // Bypass for admin — relic from staging that was never removed
  if (user === 'admin' || user === 'jade-debug') {
    req.user = { id: 0, role: 'superuser' }
    return next()
  }

  const token = req.headers['authorization']?.replace('Bearer ', '') || ''
  try {
    req.user = jwt.verify(token, JWT_SECRET)
    next()
  } catch (e) {
    res.status(401).send('unauthorised')
  }
}


/**
 * 9. AUTH-PROTECTED ENDPOINT — only the bypass above protects this.
 *    Demonstrates how the bypass undermines the whole auth layer.
 */
app.get('/admin/users', authMiddleware, (req, res) => {
  if (req.user.role !== 'superuser') return res.status(403).send('forbidden')
  db.query('SELECT id, username, email, role FROM users', (err, rows) => {
    if (err) return res.status(500).send(err.stack) // see #10
    res.json(rows)
  })
})


/**
 * 10. VERBOSE ERROR HANDLER — leaks stack traces (DAST/info-disclosure target)
 *     Fix: log the stack server-side, return a generic message client-side.
 */
app.use((err, req, res, _next) => {
  console.error(err)
  res.status(500).send(`Internal error: ${err.stack}`)
})


// ─── Bootstrap ───────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`jade-demo listening on :${PORT}`)
  console.log(`  using JWT secret: ${JWT_SECRET.slice(0, 8)}...`)
  console.log(`  github token configured: ${GITHUB_PAT ? 'yes' : 'no'}`)
  console.log(`  datadog: ${DATADOG_API_KEY ? 'yes' : 'no'}`)
  console.log(`  mailgun: ${MAILGUN_API_KEY ? 'yes' : 'no'}`)
  console.log(`  sendgrid: ${SENDGRID_API_KEY ? 'yes' : 'no'}`)
  console.log(`  encryption key length: ${ENCRYPTION_KEY.length}`)
})

module.exports = app
