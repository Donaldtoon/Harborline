require('dotenv').config();
const crypto = require('node:crypto');
const path = require('node:path');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const { z } = require('zod');
const { pool } = require('./db');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const production = process.env.NODE_ENV === 'production';
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  if (production) throw new Error('SESSION_SECRET must be set to a random string of at least 32 characters.');
  console.warn('WARNING: Set SESSION_SECRET to a random string of at least 32 characters before deployment.');
}
app.disable('x-powered-by');
if (production) app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"], scriptSrc: ["'self'"], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"] } } }));
app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));
app.use(session({
  store: new PgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  name: 'harborline.sid', secret: process.env.SESSION_SECRET || 'local-development-secret-change-this-000000',
  resave: false, saveUninitialized: false, rolling: true,
  cookie: { httpOnly: true, sameSite: 'lax', secure: production || process.env.COOKIE_SECURE === 'true', maxAge: 1000 * 60 * 60 }
}));
app.use(express.static(path.join(__dirname, '..', 'public'), { maxAge: production ? '1h' : 0 }));
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many attempts. Please wait and try again.' } });
const emailSchema = z.string().email().max(254).transform(v => v.toLowerCase().trim());
const amountSchema = z.coerce.number().finite().positive().max(1000000).refine(v => Math.round(v * 100) === v * 100, 'Amount must have no more than two decimal places.');
const text = (max = 200) => z.string().trim().min(1).max(max);
const safeUser = u => ({ id: u.id, email: u.email, role: u.role, firstName: u.first_name, lastName: u.last_name, phone: u.phone, addressLine1: u.address_line1, addressLine2: u.address_line2, city: u.city, state: u.state, postalCode: u.postal_code, status: u.status, createdAt: u.created_at });
const money = n => Number(n).toFixed(2);
const ref = prefix => `${prefix}-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
function requireAuth(req, res, next) { if (!req.session.userId) return res.status(401).json({ error: 'Please sign in to continue.' }); next(); }
function requireAdmin(req, res, next) { if (req.session.role !== 'admin') return res.status(403).json({ error: 'Administrator access required.' }); next(); }
function requireCsrf(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method) || ['/api/login', '/api/logout'].includes(req.originalUrl.split('?')[0])) return next();
  if (!req.session.csrfToken || req.get('x-csrf-token') !== req.session.csrfToken) return res.status(403).json({ error: 'Security token expired. Refresh the page and try again.' });
  next();
}
app.use('/api', requireCsrf);
async function getAccounts(userId) {
  const { rows } = await pool.query('SELECT id,account_type,account_number,routing_number,current_balance,available_balance,status,created_at FROM bank_accounts WHERE user_id=$1 ORDER BY account_type', [userId]);
  return rows.map(a => ({ id: a.id, type: a.account_type, accountNumber: a.account_number, routingNumber: a.routing_number, currentBalance: money(a.current_balance), availableBalance: money(a.available_balance), status: a.status, createdAt: a.created_at }));
}
async function createAccounts(client, userId) {
  for (const type of ['checking', 'savings']) {
    const accountNumber = `SIM${crypto.randomInt(1000000000, 9999999999)}`;
    await client.query('INSERT INTO bank_accounts(user_id,account_type,account_number,routing_number) VALUES($1,$2,$3,$4)', [userId, type, accountNumber, 'SIM-ROUTING-ONLY']);
  }
}
async function audit(actorId, action, targetId, details = {}) { await pool.query('INSERT INTO audit_logs(actor_id,action,target_id,details) VALUES($1,$2,$3,$4)', [actorId || null, action, targetId || null, JSON.stringify(details)]); }
app.get('/api/health', async (_req, res) => { try { await pool.query('SELECT 1'); res.json({ status: 'ok', database: 'connected' }); } catch { res.status(503).json({ status: 'error', database: 'unavailable' }); } });
app.get('/api/csrf', (req, res) => { req.session.csrfToken ||= crypto.randomBytes(32).toString('hex'); res.json({ csrfToken: req.session.csrfToken }); });
app.post('/api/register', async (req, res, next) => {
  const schema = z.object({ email: emailSchema, password: z.string().min(12).max(128), firstName: text(80), lastName: text(80) });
  const parsed = schema.safeParse(req.body); if (!parsed.success) return res.status(400).json({ error: 'Enter a valid email, first and last name, and a password of at least 12 characters.' });
  const { email, password, firstName, lastName } = parsed.data;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await client.query("INSERT INTO users(email,password_hash,first_name,last_name) VALUES($1,$2,$3,$4) RETURNING *", [email, hash, firstName, lastName]);
    await createAccounts(client, rows[0].id);
    await client.query('COMMIT');
    req.session.userId = rows[0].id; req.session.role = rows[0].role; req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    res.status(201).json({ user: safeUser(rows[0]), csrfToken: req.session.csrfToken });
  } catch (err) { await client.query('ROLLBACK'); if (err.code === '23505') return res.status(409).json({ error: 'An account with that email already exists.' }); next(err); }
  finally { client.release(); }
});
app.post('/api/login', loginLimiter, async (req, res, next) => {
  const parsed = z.object({ email: emailSchema, password: z.string().min(1).max(128) }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Enter your email and password.' });
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [parsed.data.email]);
    const user = rows[0];
    if (!user || user.status !== 'active' || !(await bcrypt.compare(parsed.data.password, user.password_hash))) return res.status(401).json({ error: 'Email or password is incorrect, or the account is inactive.' });
    req.session.regenerate(err => {
      if (err) return next(err);
      req.session.userId = user.id; req.session.role = user.role; req.session.csrfToken = crypto.randomBytes(32).toString('hex');
      req.session.save(err2 => { if (err2) return next(err2); res.json({ user: safeUser(user), csrfToken: req.session.csrfToken }); });
    });
  } catch (err) { next(err); }
});
app.post('/api/logout', (req, res, next) => req.session.destroy(err => { if (err) return next(err); res.clearCookie('harborline.sid'); res.json({ success: true }); }));
app.get('/api/me', requireAuth, async (req, res, next) => { try { const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [req.session.userId]); if (!rows[0] || rows[0].status !== 'active') { req.session.destroy(() => {}); return res.status(401).json({ error: 'Account is inactive.' }); } res.json({ user: safeUser(rows[0]), accounts: await getAccounts(req.session.userId), csrfToken: req.session.csrfToken }); } catch (e) { next(e); } });
app.patch('/api/profile', requireAuth, async (req, res, next) => {
  const schema = z.object({ phone: z.string().trim().max(40).optional(), addressLine1: z.string().trim().max(150).optional(), addressLine2: z.string().trim().max(150).optional(), city: z.string().trim().max(80).optional(), state: z.string().trim().max(80).optional(), postalCode: z.string().trim().max(20).optional() }).strict();
  const p = schema.safeParse(req.body); if (!p.success) return res.status(400).json({ error: 'Check the profile fields and try again.' });
  try { const keys = { phone: 'phone', addressLine1: 'address_line1', addressLine2: 'address_line2', city: 'city', state: 'state', postalCode: 'postal_code' }; const fields = Object.keys(p.data); if (!fields.length) return res.status(400).json({ error: 'No profile changes provided.' }); const sets = fields.map((k, i) => `${keys[k]}=$${i + 2}`); const vals = fields.map(k => p.data[k]); const { rows } = await pool.query(`UPDATE users SET ${sets.join(',')},updated_at=NOW() WHERE id=$1 RETURNING *`, [req.session.userId, ...vals]); res.json({ user: safeUser(rows[0]) }); } catch (e) { next(e); }
});
app.get('/api/transactions', requireAuth, async (req, res, next) => {
  const page = Math.max(1, Math.min(10000, Number.parseInt(req.query.page, 10) || 1)); const limit = Math.max(1, Math.min(50, Number.parseInt(req.query.limit, 10) || 10));
  const schema = z.object({ accountId: z.string().uuid().optional(), type: z.enum(['deposit','withdrawal','transfer_in','transfer_out','admin_adjustment']).optional(), search: z.string().max(100).optional(), from: z.string().date().optional(), to: z.string().date().optional() });
  const filters = schema.safeParse({ accountId: req.query.accountId, type: req.query.type, search: req.query.search, from: req.query.from, to: req.query.to }); if (!filters.success) return res.status(400).json({ error: 'Invalid transaction filters.' });
  try {
    const params = [req.session.userId]; let where = 't.user_id=$1'; const f = filters.data;
    if (f.accountId) { params.push(f.accountId); where += ` AND t.account_id=$${params.length} AND EXISTS(SELECT 1 FROM bank_accounts a WHERE a.id=t.account_id AND a.user_id=$1)`; }
    if (f.type) { params.push(f.type); where += ` AND t.type=$${params.length}`; }
    if (f.search) { params.push(`%${f.search}%`); where += ` AND (t.description ILIKE $${params.length} OR t.reference ILIKE $${params.length})`; }
    if (f.from) { params.push(f.from); where += ` AND t.created_at >= $${params.length}::date`; }
    if (f.to) { params.push(f.to); where += ` AND t.created_at < ($${params.length}::date + INTERVAL '1 day')`; }
    const count = await pool.query(`SELECT COUNT(*)::int AS count FROM transactions t WHERE ${where}`, params);
    params.push(limit, (page - 1) * limit);
    const { rows } = await pool.query(`SELECT t.*,a.account_type FROM transactions t JOIN bank_accounts a ON a.id=t.account_id WHERE ${where} ORDER BY t.created_at DESC LIMIT $${params.length - 1} OFFSET $${params.length}`, params);
    res.json({ transactions: rows.map(t => ({ id: t.id, reference: t.reference, accountId: t.account_id, accountType: t.account_type, type: t.type, description: t.description, amount: money(t.amount), direction: t.direction, balanceAfter: money(t.balance_after), status: t.status, createdAt: t.created_at })), page, limit, total: count.rows[0].count });
  } catch (e) { next(e); }
});
async function operate(req, res, next, operation) {
  const parsed = z.object({ accountId: z.string().uuid(), amount: amountSchema, description: z.string().trim().max(160).optional(), idempotencyKey: z.string().min(8).max(100).optional() }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Provide an account, a positive amount with up to two decimal places, and a valid description.' });
  const { accountId, amount, description = '', idempotencyKey } = parsed.data; const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (idempotencyKey) { const prev = await client.query('SELECT response FROM idempotency_keys WHERE user_id=$1 AND key=$2 FOR UPDATE', [req.session.userId, idempotencyKey]); if (prev.rowCount && prev.rows[0].response) { await client.query('COMMIT'); return res.json(prev.rows[0].response); } if (!prev.rowCount) await client.query('INSERT INTO idempotency_keys(user_id,key) VALUES($1,$2) ON CONFLICT DO NOTHING', [req.session.userId,idempotencyKey]); }
    const found = await client.query('SELECT * FROM bank_accounts WHERE id=$1 AND user_id=$2 AND status=\'active\' FOR UPDATE', [accountId, req.session.userId]);
    if (!found.rowCount) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Active account not found.' }); }
    const account = found.rows[0];
    if (operation === 'withdrawal' && Number(account.available_balance) < amount) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Insufficient available balance.' }); }
    const delta = operation === 'deposit' ? amount : -amount;
    const updated = await client.query('UPDATE bank_accounts SET current_balance=current_balance+$2,available_balance=available_balance+$2 WHERE id=$1 RETURNING current_balance', [accountId, delta]);
    const transaction = await client.query('INSERT INTO transactions(reference,account_id,user_id,type,description,amount,direction,balance_after,idempotency_key) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *', [ref('HL'),accountId,req.session.userId,operation,description || (operation === 'deposit' ? 'Simulated deposit' : 'Simulated withdrawal'),amount,operation === 'deposit' ? 'credit' : 'debit',updated.rows[0].current_balance,idempotencyKey || null]);
    const response = { success: true, transaction: { reference: transaction.rows[0].reference, type: operation, amount: money(amount), balanceAfter: money(updated.rows[0].current_balance), createdAt: transaction.rows[0].created_at }, accounts: await getAccounts(req.session.userId) };
    if (idempotencyKey) await client.query('UPDATE idempotency_keys SET response=$3 WHERE user_id=$1 AND key=$2', [req.session.userId,idempotencyKey,JSON.stringify(response)]);
    await client.query('COMMIT'); res.json(response);
  } catch (e) { await client.query('ROLLBACK'); next(e); } finally { client.release(); }
}
app.post('/api/deposit', requireAuth, (req,res,next) => operate(req,res,next,'deposit'));
app.post('/api/withdrawal', requireAuth, (req,res,next) => operate(req,res,next,'withdrawal'));
app.post('/api/transfer', requireAuth, async (req,res,next) => {
  const p = z.object({ fromAccountId: z.string().uuid(), toAccountId: z.string().uuid().optional(), destinationEmail: emailSchema.optional(), amount: amountSchema, description: z.string().trim().max(160).optional(), idempotencyKey: z.string().min(8).max(100).optional() }).refine(v => v.toAccountId || v.destinationEmail, 'Destination required').safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: 'Choose a source account, destination account or customer email, and valid amount.' });
  const v = p.data; const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (v.idempotencyKey) { const prev = await client.query('SELECT response FROM idempotency_keys WHERE user_id=$1 AND key=$2 FOR UPDATE', [req.session.userId,v.idempotencyKey]); if (prev.rowCount && prev.rows[0].response) { await client.query('COMMIT'); return res.json(prev.rows[0].response); } if (!prev.rowCount) await client.query('INSERT INTO idempotency_keys(user_id,key) VALUES($1,$2) ON CONFLICT DO NOTHING', [req.session.userId,v.idempotencyKey]); }
    const srcResult = await client.query('SELECT * FROM bank_accounts WHERE id=$1 AND user_id=$2 AND status=\'active\' FOR UPDATE', [v.fromAccountId,req.session.userId]);
    if (!srcResult.rowCount) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Source account not found.' }); }
    const src = srcResult.rows[0]; let dest;
    if (v.toAccountId) { const d = await client.query('SELECT * FROM bank_accounts WHERE id=$1 AND status=\'active\' FOR UPDATE', [v.toAccountId]); dest = d.rows[0]; }
    else { const d = await client.query('SELECT a.* FROM bank_accounts a JOIN users u ON u.id=a.user_id WHERE u.email=$1 AND a.account_type=$2 AND a.status=\'active\' FOR UPDATE OF a', [v.destinationEmail,src.account_type]); dest = d.rows[0]; }
    if (!dest) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Destination account not found.' }); }
    if (dest.id === src.id) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Choose a different destination account.' }); }
    if (Number(src.available_balance) < v.amount) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Insufficient available balance.' }); }
    await client.query('UPDATE bank_accounts SET current_balance=current_balance-$2,available_balance=available_balance-$2 WHERE id=$1', [src.id,v.amount]);
    const dstUpdate = await client.query('UPDATE bank_accounts SET current_balance=current_balance+$2,available_balance=available_balance+$2 WHERE id=$1 RETURNING current_balance', [dest.id,v.amount]);
    const srcUpdate = await client.query('SELECT current_balance FROM bank_accounts WHERE id=$1', [src.id]); const description = v.description || 'Simulated internal transfer'; const transferRef = ref('TRF');
    await client.query('INSERT INTO transactions(reference,account_id,related_account_id,user_id,type,description,amount,direction,balance_after,idempotency_key) VALUES($1,$2,$3,$4,\'transfer_out\',$5,$6,\'debit\',$7,$8)', [transferRef,src.id,dest.id,req.session.userId,description,v.amount,srcUpdate.rows[0].current_balance,v.idempotencyKey || null]);
    await client.query('INSERT INTO transactions(reference,account_id,related_account_id,user_id,type,description,amount,direction,balance_after) VALUES($1,$2,$3,$4,\'transfer_in\',$5,$6,\'credit\',$7)', [ref('TRF'),dest.id,src.id,dest.user_id,description,v.amount,dstUpdate.rows[0].current_balance]);
    const response = { success: true, reference: transferRef, amount: money(v.amount), message: 'Simulated transfer completed.', accounts: await getAccounts(req.session.userId) };
    if (v.idempotencyKey) await client.query('UPDATE idempotency_keys SET response=$3 WHERE user_id=$1 AND key=$2', [req.session.userId,v.idempotencyKey,JSON.stringify(response)]);
    await client.query('COMMIT'); res.json(response);
  } catch (e) { await client.query('ROLLBACK'); next(e); } finally { client.release(); }
});
app.get('/api/support', requireAuth, async (req,res,next) => { try { const { rows } = await pool.query('SELECT t.*, (SELECT COUNT(*)::int FROM support_messages m WHERE m.ticket_id=t.id) AS message_count FROM support_tickets t WHERE t.user_id=$1 ORDER BY t.updated_at DESC', [req.session.userId]); res.json({ tickets: rows }); } catch(e){next(e);} });
app.post('/api/support', requireAuth, async (req,res,next) => { const p = z.object({ subject: text(120), message: text(2000) }).safeParse(req.body); if(!p.success) return res.status(400).json({error:'Enter a subject and message.'}); const c=await pool.connect(); try { await c.query('BEGIN'); const t=await c.query('INSERT INTO support_tickets(reference,user_id,subject) VALUES($1,$2,$3) RETURNING *',[ref('TKT'),req.session.userId,p.data.subject]); await c.query('INSERT INTO support_messages(ticket_id,sender_id,message) VALUES($1,$2,$3)',[t.rows[0].id,req.session.userId,p.data.message]); await c.query('COMMIT'); res.status(201).json({ticket:t.rows[0]}); } catch(e){await c.query('ROLLBACK');next(e);} finally{c.release();} });
app.get('/api/support/:id/messages', requireAuth, async(req,res,next)=>{try{const own=await pool.query('SELECT id FROM support_tickets WHERE id=$1 AND user_id=$2',[req.params.id,req.session.userId]); if(!own.rowCount && req.session.role!=='admin')return res.status(404).json({error:'Ticket not found.'}); const {rows}=await pool.query('SELECT m.id,m.message,m.created_at,u.first_name,u.last_name,u.role FROM support_messages m JOIN users u ON u.id=m.sender_id WHERE m.ticket_id=$1 ORDER BY m.created_at',[req.params.id]);res.json({messages:rows});}catch(e){next(e);}});
app.post('/api/support/:id/messages', requireAuth, async(req,res,next)=>{const p=z.object({message:text(2000)}).safeParse(req.body);if(!p.success)return res.status(400).json({error:'Enter a message.'});const c=await pool.connect();try{await c.query('BEGIN');const t=await c.query('SELECT * FROM support_tickets WHERE id=$1 FOR UPDATE',[req.params.id]);if(!t.rowCount|| (req.session.role!=='admin'&&t.rows[0].user_id!==req.session.userId)){await c.query('ROLLBACK');return res.status(404).json({error:'Ticket not found.'});}await c.query('INSERT INTO support_messages(ticket_id,sender_id,message) VALUES($1,$2,$3)',[req.params.id,req.session.userId,p.data.message]);await c.query("UPDATE support_tickets SET updated_at=NOW(),status=CASE WHEN $2='admin' AND status='open' THEN 'in_progress' ELSE status END WHERE id=$1",[req.params.id,req.session.role]);await c.query('COMMIT');res.status(201).json({success:true});}catch(e){await c.query('ROLLBACK');next(e);}finally{c.release();}});
// Administrator-only routes. No secret URL or hardcoded master account is used.
app.get('/api/admin/overview', requireAuth, requireAdmin, async(req,res,next)=>{try{const [u,a,t,s,l]=await Promise.all([pool.query("SELECT COUNT(*)::int AS count FROM users WHERE role='customer'"),pool.query('SELECT COUNT(*)::int AS count FROM bank_accounts'),pool.query('SELECT COUNT(*)::int AS count FROM transactions'),pool.query("SELECT COUNT(*)::int AS count FROM support_tickets WHERE status <> 'closed'"),pool.query('SELECT id,actor_id,action,target_id,details,created_at FROM audit_logs ORDER BY created_at DESC LIMIT 50')]);res.json({customers:u.rows[0].count,accounts:a.rows[0].count,transactions:t.rows[0].count,openTickets:s.rows[0].count,auditLogs:l.rows});}catch(e){next(e);}});
app.get('/api/admin/customers', requireAuth, requireAdmin, async(req,res,next)=>{try{const search=String(req.query.search||'').slice(0,100);const {rows}=await pool.query("SELECT id,email,first_name,last_name,phone,status,created_at FROM users WHERE role='customer' AND ($1='' OR email ILIKE $2 OR first_name ILIKE $2 OR last_name ILIKE $2) ORDER BY created_at DESC LIMIT 200",[search,`%${search}%`]);res.json({customers:rows});}catch(e){next(e);}});
app.post('/api/admin/customers', requireAuth, requireAdmin, async(req,res,next)=>{const p=z.object({email:emailSchema,password:z.string().min(12).max(128),firstName:text(80),lastName:text(80)}).safeParse(req.body);if(!p.success)return res.status(400).json({error:'Provide valid customer details and a password of at least 12 characters.'});const c=await pool.connect();try{await c.query('BEGIN');const h=await bcrypt.hash(p.data.password,12);const u=await c.query("INSERT INTO users(email,password_hash,first_name,last_name) VALUES($1,$2,$3,$4) RETURNING id,email,first_name,last_name,status,created_at",[p.data.email,h,p.data.firstName,p.data.lastName]);await createAccounts(c,u.rows[0].id);await c.query('INSERT INTO audit_logs(actor_id,action,target_id,details) VALUES($1,$2,$3,$4)',[req.session.userId,'customer.created',u.rows[0].id,JSON.stringify({email:p.data.email})]);await c.query('COMMIT');res.status(201).json({customer:u.rows[0]});}catch(e){await c.query('ROLLBACK');if(e.code==='23505')return res.status(409).json({error:'Email already exists.'});next(e);}finally{c.release();}});
app.patch('/api/admin/customers/:id/status', requireAuth, requireAdmin, async(req,res,next)=>{const p=z.object({status:z.enum(['active','inactive'])}).safeParse(req.body);if(!p.success)return res.status(400).json({error:'Invalid account status.'});try{const {rows}=await pool.query("UPDATE users SET status=$2,updated_at=NOW() WHERE id=$1 AND role='customer' RETURNING id,email,status",[req.params.id,p.data.status]);if(!rows.length)return res.status(404).json({error:'Customer not found.'});await audit(req.session.userId,'customer.status_changed',req.params.id,{status:p.data.status});res.json({customer:rows[0]});}catch(e){next(e);}});
app.patch('/api/admin/customers/:id/password', requireAuth, requireAdmin, async(req,res,next)=>{const p=z.object({password:z.string().min(12).max(128)}).safeParse(req.body);if(!p.success)return res.status(400).json({error:'New password must be at least 12 characters.'});try{const hash=await bcrypt.hash(p.data.password,12);const {rows}=await pool.query("UPDATE users SET password_hash=$2,updated_at=NOW() WHERE id=$1 AND role='customer' RETURNING id,email",[req.params.id,hash]);if(!rows.length)return res.status(404).json({error:'Customer not found.'});await audit(req.session.userId,'customer.password_reset',req.params.id,{email:rows[0].email});res.json({success:true,message:'Customer password reset. Share the new password with the customer through a secure channel.'});}catch(e){next(e);}});
app.post('/api/admin/customers/:id/adjustments', requireAuth, requireAdmin, async(req,res,next)=>{const p=z.object({accountId:z.string().uuid(),amount:amountSchema,direction:z.enum(['credit','debit']),description:z.string().trim().max(160).optional()}).safeParse(req.body);if(!p.success)return res.status(400).json({error:'Provide a valid account, positive amount, and adjustment direction.'});const c=await pool.connect();try{await c.query('BEGIN');const a=await c.query('SELECT * FROM bank_accounts WHERE id=$1 AND user_id=$2 FOR UPDATE',[p.data.accountId,req.params.id]);if(!a.rowCount){await c.query('ROLLBACK');return res.status(404).json({error:'Customer account not found.'});}const current=Number(a.rows[0].current_balance);if(p.data.direction==='debit'&&current<p.data.amount){await c.query('ROLLBACK');return res.status(400).json({error:'Adjustment would make the account balance negative.'});}const delta=p.data.direction==='credit'?p.data.amount:-p.data.amount;const u=await c.query('UPDATE bank_accounts SET current_balance=current_balance+$2,available_balance=available_balance+$2 WHERE id=$1 RETURNING current_balance',[p.data.accountId,delta]);const tr=await c.query("INSERT INTO transactions(reference,account_id,user_id,type,description,amount,direction,balance_after) VALUES($1,$2,$3,'admin_adjustment',$4,$5,$6,$7) RETURNING reference",[ref('ADJ'),p.data.accountId,req.params.id,p.data.description||'Administrator simulated balance adjustment',p.data.amount,p.data.direction,u.rows[0].current_balance]);await c.query('INSERT INTO audit_logs(actor_id,action,target_id,details) VALUES($1,$2,$3,$4)',[req.session.userId,'account.balance_adjusted',p.data.accountId,JSON.stringify({customerId:req.params.id,direction:p.data.direction,amount:money(p.data.amount),reference:tr.rows[0].reference})]);await c.query('COMMIT');res.json({success:true,reference:tr.rows[0].reference,balance:money(u.rows[0].current_balance)});}catch(e){await c.query('ROLLBACK');next(e);}finally{c.release();}});
app.get('/api/admin/tickets', requireAuth, requireAdmin, async(req,res,next)=>{try{const {rows}=await pool.query('SELECT t.*,u.email,u.first_name,u.last_name FROM support_tickets t JOIN users u ON u.id=t.user_id ORDER BY t.updated_at DESC LIMIT 200');res.json({tickets:rows});}catch(e){next(e);}});
app.patch('/api/admin/tickets/:id', requireAuth, requireAdmin, async(req,res,next)=>{const p=z.object({status:z.enum(['open','in_progress','closed'])}).safeParse(req.body);if(!p.success)return res.status(400).json({error:'Invalid ticket status.'});try{const {rows}=await pool.query('UPDATE support_tickets SET status=$2,updated_at=NOW() WHERE id=$1 RETURNING *',[req.params.id,p.data.status]);if(!rows.length)return res.status(404).json({error:'Ticket not found.'});await audit(req.session.userId,'support.status_changed',req.params.id,{status:p.data.status});res.json({ticket:rows[0]});}catch(e){next(e);}});
app.get('/api/admin/customers/:id/accounts', requireAuth, requireAdmin, async(req,res,next)=>{try{const {rows}=await pool.query('SELECT id,account_type,account_number,current_balance,available_balance,status FROM bank_accounts WHERE user_id=$1 ORDER BY account_type',[req.params.id]);res.json({accounts:rows.map(a=>({...a,current_balance:money(a.current_balance),available_balance:money(a.available_balance)}))});}catch(e){next(e);}});
app.use('/api', (_req,res)=>res.status(404).json({error:'API endpoint not found.'}));
app.get('*', (req,res,next)=>{if(req.path.startsWith('/api/'))return next();res.sendFile(path.join(__dirname,'..','public','index.html'));});
app.use((err,req,res,_next)=>{console.error('Request failed:',err.message);if(res.headersSent)return;res.status(500).json({error:production?'Something went wrong. Please try again.':err.message});});
if (require.main === module) app.listen(PORT, ()=>console.log(`Harborline Banking Simulator running on port ${PORT}`));
module.exports = { app, amountSchema };
