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

if (
  production &&
  (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)
) {
  throw new Error(
    'SESSION_SECRET must be set to a random string of at least 32 characters.'
  );
}

app.disable('x-powered-by');

if (production) {
  app.set('trust proxy', 1);
}

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'']
      }
    }
  })
);

app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));

// The HTML, CSS, and JavaScript files are in the repository root.
app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/styles.css', (_req, res, next) => {
  res.sendFile(path.join(__dirname, 'styles.css'), err => {
    if (err) next(err);
  });
});

app.get('/app.js', (_req, res, next) => {
  res.sendFile(path.join(__dirname, 'app.js'), err => {
    if (err) next(err);
  });
});

// Serve other existing static assets from the repository root.
app.use(
  express.static(__dirname, {
    index: false,
    maxAge: production ? '1h' : 0,
    dotfiles: 'ignore'
  })
);

app.use(
  session({
    store: new PgSession({
      pool,
      tableName: 'user_sessions',
      createTableIfMissing: true
    }),
    name: 'harborline.sid',
    secret:
      process.env.SESSION_SECRET ||
      'local-development-secret-change-this-000000',
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: production || process.env.COOKIE_SECURE === 'true',
      maxAge: 1000 * 60 * 60
    }
  })
);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    error: 'Too many attempts. Please wait and try again.'
  }
});

const emailSchema = z
  .string()
  .email()
  .max(254)
  .transform(value => value.toLowerCase().trim());

const amountSchema = z
  .coerce
  .number()
  .finite()
  .positive()
  .max(1000000)
  .refine(
    value => Math.round(value * 100) === value * 100,
    'Amount must have no more than two decimal places.'
  );

const text = (max = 200) => z.string().trim().min(1).max(max);

const safeUser = user => ({
  id: user.id,
  email: user.email,
  role: user.role,
  firstName: user.first_name,
  lastName: user.last_name,
  phone: user.phone,
  addressLine1: user.address_line1,
  addressLine2: user.address_line2,
  city: user.city,
  state: user.state,
  postalCode: user.postal_code,
  status: user.status,
  createdAt: user.created_at
});

const money = value => Number(value).toFixed(2);

const ref = prefix =>
  `${prefix}-${Date.now().toString(36).toUpperCase()}-${crypto
    .randomBytes(4)
    .toString('hex')
    .toUpperCase()}`;

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: 'Please sign in to continue.'
    });
  }

  next();
}

function requireAdmin(req, res, next) {
  if (req.session.role !== 'admin') {
    return res.status(403).json({
      error: 'Administrator access required.'
    });
  }

  next();
}

function requireCsrf(req, res, next) {
  const publicEndpoints = ['/api/login', '/api/logout', '/api/register'];

  if (
    ['GET', 'HEAD', 'OPTIONS'].includes(req.method) ||
    publicEndpoints.includes(req.path)
  ) {
    return next();
  }

  if (
    !req.session.csrfToken ||
    req.get('x-csrf-token') !== req.session.csrfToken
  ) {
    return res.status(403).json({
      error: 'Security token expired. Refresh the page and try again.'
    });
  }

  next();
}

app.use('/api', requireCsrf);

async function getAccounts(userId) {
  const { rows } = await pool.query(
    `SELECT id, account_type, account_number, routing_number,
            current_balance, available_balance, status, created_at
     FROM bank_accounts
     WHERE user_id = $1
     ORDER BY account_type`,
    [userId]
  );

  return rows.map(account => ({
    id: account.id,
    type: account.account_type,
    accountNumber: account.account_number,
    routingNumber: account.routing_number,
    currentBalance: money(account.current_balance),
    availableBalance: money(account.available_balance),
    status: account.status,
    createdAt: account.created_at
  }));
}

async function createAccounts(client, userId) {
  for (const type of ['checking', 'savings']) {
    const accountNumber = `SIM${crypto.randomInt(1000000000, 9999999999)}`;

    await client.query(
      `INSERT INTO bank_accounts
       (user_id, account_type, account_number, routing_number)
       VALUES ($1, $2, $3, $4)`,
      [userId, type, accountNumber, 'SIM-ROUTING-ONLY']
    );
  }
}

async function audit(actorId, action, targetId, details = {}) {
  await pool.query(
    `INSERT INTO audit_logs(actor_id, action, target_id, details)
     VALUES ($1, $2, $3, $4)`,
    [
      actorId || null,
      action,
      targetId || null,
      JSON.stringify(details)
    ]
  );
}

// Health check
app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');

    res.json({
      status: 'ok',
      database: 'connected'
    });
  } catch (error) {
    console.error('Health check database failure:', error.message);

    res.status(503).json({
      status: 'error',
      database: 'unavailable'
    });
  }
});

// CSRF token
app.get('/api/csrf', (req, res) => {
  req.session.csrfToken ||= crypto.randomBytes(32).toString('hex');

  res.json({
    csrfToken: req.session.csrfToken
  });
});

// Register
app.post('/api/register', async (req, res, next) => {
  const schema = z.object({
    email: emailSchema,
    password: z.string().min(12).max(128),
    firstName: text(80),
    lastName: text(80)
  });

  const parsed = schema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      error:
        'Enter a valid email, first and last name, and a password of at least 12 characters.'
    });
  }

  const { email, password, firstName, lastName } = parsed.data;
  let client;

  try {
    client = await pool.connect();
    await client.query('BEGIN');

    const hash = await bcrypt.hash(password, 12);

    const result = await client.query(
      `INSERT INTO users(email, password_hash, first_name, last_name)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [email, hash, firstName, lastName]
    );

    const user = result.rows[0];

    await createAccounts(client, user.id);
    await client.query('COMMIT');

    req.session.userId = user.id;
    req.session.role = user.role;
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');

    req.session.save(error => {
      if (error) return next(error);

      res.status(201).json({
        user: safeUser(user),
        csrfToken: req.session.csrfToken
      });
    });
  } catch (error) {
    if (client) {
      try {
        await client.query('ROLLBACK');
      } catch {}
    }

    if (error.code === '23505') {
      return res.status(409).json({
        error: 'An account with that email already exists.'
      });
    }

    next(error);
  } finally {
    if (client) client.release();
  }
});

// Login
app.post('/api/login', loginLimiter, async (req, res, next) => {
  const parsed = z
    .object({
      email: emailSchema,
      password: z.string().min(1).max(128)
    })
    .safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      error: 'Enter your email and password.'
    });
  }

  try {
    const { rows } = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [parsed.data.email]
    );

    const user = rows[0];

    if (
      !user ||
      user.status !== 'active' ||
      !(await bcrypt.compare(parsed.data.password, user.password_hash))
    ) {
      return res.status(401).json({
        error: 'Email or password is incorrect, or the account is inactive.'
      });
    }

    req.session.regenerate(error => {
      if (error) return next(error);

      req.session.userId = user.id;
      req.session.role = user.role;
      req.session.csrfToken = crypto.randomBytes(32).toString('hex');

      req.session.save(saveError => {
        if (saveError) return next(saveError);

        res.json({
          user: safeUser(user),
          csrfToken: req.session.csrfToken
        });
      });
    });
  } catch (error) {
    next(error);
  }
});

// Logout
app.post('/api/logout', (req, res, next) => {
  req.session.destroy(error => {
    if (error) return next(error);

    res.clearCookie('harborline.sid');

    res.json({
      success: true
    });
  });
});

// Current user and accounts
app.get('/api/me', requireAuth, async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [req.session.userId]
    );

    if (!rows[0] || rows[0].status !== 'active') {
      req.session.destroy(() => {});

      return res.status(401).json({
        error: 'Account is inactive.'
      });
    }

    res.json({
      user: safeUser(rows[0]),
      accounts: await getAccounts(req.session.userId),
      csrfToken: req.session.csrfToken
    });
  } catch (error) {
    next(error);
  }
});

// Update profile
app.patch('/api/profile', requireAuth, async (req, res, next) => {
  const schema = z
    .object({
      phone: z.string().trim().max(40).optional(),
      addressLine1: z.string().trim().max(150).optional(),
      addressLine2: z.string().trim().max(150).optional(),
      city: z.string().trim().max(80).optional(),
      state: z.string().trim().max(80).optional(),
      postalCode: z.string().trim().max(20).optional()
    })
    .strict();

  const parsed = schema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      error: 'Check the profile fields and try again.'
    });
  }

  const keys = {
    phone: 'phone',
    addressLine1: 'address_line1',
    addressLine2: 'address_line2',
    city: 'city',
    state: 'state',
    postalCode: 'postal_code'
  };

  const fields = Object.keys(parsed.data);

  if (!fields.length) {
    return res.status(400).json({
      error: 'No profile changes provided.'
    });
  }

  try {
    const sets = fields.map((key, index) => `${keys[key]} = $${index + 2}`);
    const values = fields.map(key => parsed.data[key]);

    const { rows } = await pool.query(
      `UPDATE users
       SET ${sets.join(', ')}, updated_at = NOW()
       WHERE id = $1
       RETURNING *`,
      [req.session.userId, ...values]
    );

    res.json({
      user: safeUser(rows[0])
    });
  } catch (error) {
    next(error);
  }
});

// Transaction history
app.get('/api/transactions', requireAuth, async (req, res, next) => {
  const page = Math.max(
    1,
    Math.min(10000, Number.parseInt(req.query.page, 10) || 1)
  );

  const limit = Math.max(
    1,
    Math.min(50, Number.parseInt(req.query.limit, 10) || 10)
  );

  const schema = z.object({
    accountId: z.string().uuid().optional(),
    type: z
      .enum([
        'deposit',
        'withdrawal',
        'transfer_in',
        'transfer_out',
        'admin_adjustment'
      ])
      .optional(),
    search: z.string().max(100).optional(),
    from: z.string().date().optional(),
    to: z.string().date().optional()
  });

  const parsed = schema.safeParse({
    accountId: req.query.accountId,
    type: req.query.type,
    search: req.query.search,
    from: req.query.from,
    to: req.query.to
  });

  if (!parsed.success) {
    return res.status(400).json({
      error: 'Invalid transaction filters.'
    });
  }

  try {
    const params = [req.session.userId];
    let where = 't.user_id = $1';
    const filters = parsed.data;

    if (filters.accountId) {
      params.push(filters.accountId);

      where += ` AND t.account_id = $${params.length}
        AND EXISTS (
          SELECT 1 FROM bank_accounts a
          WHERE a.id = t.account_id AND a.user_id = $1
        )`;
    }

    if (filters.type) {
      params.push(filters.type);
      where += ` AND t.type = $${params.length}`;
    }

    if (filters.search) {
      params.push(`%${filters.search}%`);
      where += ` AND (
        t.description ILIKE $${params.length}
        OR t.reference ILIKE $${params.length}
      )`;
    }

    if (filters.from) {
      params.push(filters.from);
      where += ` AND t.created_at >= $${params.length}::date`;
    }

    if (filters.to) {
      params.push(filters.to);
      where += ` AND t.created_at < ($${params.length}::date + INTERVAL '1 day')`;
    }

    const count = await pool.query(
      `SELECT COUNT(*)::int AS count
       FROM transactions t
       WHERE ${where}`,
      params
    );

    const queryParams = [...params, limit, (page - 1) * limit];

    const { rows } = await pool.query(
      `SELECT t.*, a.account_type
       FROM transactions t
       JOIN bank_accounts a ON a.id = t.account_id
       WHERE ${where}
       ORDER BY t.created_at DESC
       LIMIT $${queryParams.length - 1}
       OFFSET $${queryParams.length}`,
      queryParams
    );

    res.json({
      transactions: rows.map(transaction => ({
        id: transaction.id,
        reference: transaction.reference,
        accountId: transaction.account_id,
        accountType: transaction.account_type,
        type: transaction.type,
        description: transaction.description,
        amount: money(transaction.amount),
        direction: transaction.direction,
        balanceAfter: money(transaction.balance_after),
        status: transaction.status,
        createdAt: transaction.created_at
      })),
      page,
      limit,
      total: count.rows[0].count
    });
  } catch (error) {
    next(error);
  }
});

// Deposit and withdrawal
async function operate(req, res, next, operation) {
  const parsed = z
    .object({
      accountId: z.string().uuid(),
      amount: amountSchema,
      description: z.string().trim().max(160).optional(),
      idempotencyKey: z.string().min(8).max(100).optional()
    })
    .safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      error:
        'Provide an account, a positive amount with up to two decimal places, and a valid description.'
    });
  }

  const {
    accountId,
    amount,
    description = '',
    idempotencyKey
  } = parsed.data;

  let client;

  try {
    client = await pool.connect();
    await client.query('BEGIN');

    if (idempotencyKey) {
      const previous = await client.query(
        `SELECT response FROM idempotency_keys
         WHERE user_id = $1 AND key = $2
         FOR UPDATE`,
        [req.session.userId, idempotencyKey]
      );

      if (previous.rowCount && previous.rows[0].response) {
        await client.query('COMMIT');
        return res.json(previous.rows[0].response);
      }
    }

    const found = await client.query(
      `SELECT * FROM bank_accounts
       WHERE id = $1 AND user_id = $2 AND status = 'active'
       FOR UPDATE`,
      [accountId, req.session.userId]
    );

    if (!found.rowCount) {
      await client.query('ROLLBACK');

      return res.status(404).json({
        error: 'Active account not found.'
      });
    }

    const account = found.rows[0];

    if (
      operation === 'withdrawal' &&
      Number(account.available_balance) < amount
    ) {
      await client.query('ROLLBACK');

      return res.status(400).json({
        error: 'Insufficient available balance.'
      });
    }

    const delta = operation === 'deposit' ? amount : -amount;

    const updated = await client.query(
      `UPDATE bank_accounts
       SET current_balance = current_balance + $2,
           available_balance = available_balance + $2
       WHERE id = $1
       RETURNING current_balance`,
      [accountId, delta]
    );

    const transaction = await client.query(
      `INSERT INTO transactions
       (reference, account_id, user_id, type, description, amount,
        direction, balance_after, idempotency_key)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [
        ref('HL'),
        accountId,
        req.session.userId,
        operation,
        description ||
          (operation === 'deposit'
            ? 'Simulated deposit'
            : 'Simulated withdrawal'),
        amount,
        operation === 'deposit' ? 'credit' : 'debit',
        updated.rows[0].current_balance,
        idempotencyKey || null
      ]
    );

    const response = {
      success: true,
      transaction: {
        reference: transaction.rows[0].reference,
        type: operation,
        amount: money(amount),
        balanceAfter: money(updated.rows[0].current_balance),
        createdAt: transaction.rows[0].created_at
      },
      accounts: await getAccounts(req.session.userId)
    };

    await client.query('COMMIT');
    res.json(response);
  } catch (error) {
    if (client) {
      try {
        await client.query('ROLLBACK');
      } catch {}
    }

    next(error);
  } finally {
    if (client) client.release();
  }
}

app.post('/api/deposit', requireAuth, (req, res, next) =>
  operate(req, res, next, 'deposit')
);

app.post('/api/withdrawal', requireAuth, (req, res, next) =>
  operate(req, res, next, 'withdrawal')
);

// Transfers
app.post('/api/transfer', requireAuth, async (req, res, next) => {
  const parsed = z
    .object({
      fromAccountId: z.string().uuid(),
      toAccountId: z.string().uuid().optional(),
      destinationEmail: emailSchema.optional(),
      amount: amountSchema,
      description: z.string().trim().max(160).optional(),
      idempotencyKey: z.string().min(8).max(100).optional()
    })
    .refine(
      value => value.toAccountId || value.destinationEmail,
      'Destination required'
    )
    .safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      error:
        'Choose a source account, destination account or customer email, and valid amount.'
    });
  }

  const value = parsed.data;
  let client;

  try {
    client = await pool.connect();
    await client.query('BEGIN');

    const sourceResult = await client.query(
      `SELECT * FROM bank_accounts
       WHERE id = $1 AND user_id = $2 AND status = 'active'
       FOR UPDATE`,
      [value.fromAccountId, req.session.userId]
    );

    if (!sourceResult.rowCount) {
      await client.query('ROLLBACK');

      return res.status(404).json({
        error: 'Source account not found.'
      });
    }

    const source = sourceResult.rows[0];
    let destination;

    if (value.toAccountId) {
      const result = await client.query(
        `SELECT * FROM bank_accounts
         WHERE id = $1 AND status = 'active'
         FOR UPDATE`,
        [value.toAccountId]
      );

      destination = result.rows[0];
    } else {
      const result = await client.query(
        `SELECT a.*
         FROM bank_accounts a
         JOIN users u ON u.id = a.user_id
         WHERE u.email = $1
           AND a.account_type = $2
           AND a.status = 'active'
         FOR UPDATE OF a`,
        [value.destinationEmail, source.account_type]
      );

      destination = result.rows[0];
    }

    if (!destination) {
      await client.query('ROLLBACK');

      return res.status(404).json({
        error: 'Destination account not found.'
      });
    }

    if (String(destination.id) === String(source.id)) {
      await client.query('ROLLBACK');

      return res.status(400).json({
        error: 'Choose a different destination account.'
      });
    }

    if (Number(source.available_balance) < value.amount) {
      await client.query('ROLLBACK');

      return res.status(400).json({
        error: 'Insufficient available balance.'
      });
    }

    await client.query(
      `UPDATE bank_accounts
       SET current_balance = current_balance - $2,
           available_balance = available_balance - $2
       WHERE id = $1`,
      [source.id, value.amount]
    );

    const destinationUpdate = await client.query(
      `UPDATE bank_accounts
       SET current_balance = current_balance + $2,
           available_balance = available_balance + $2
       WHERE id = $1
       RETURNING current_balance`,
      [destination.id, value.amount]
    );

    const sourceUpdate = await client.query(
      'SELECT current_balance FROM bank_accounts WHERE id = $1',
      [source.id]
    );

    const description =
      value.description || 'Simulated internal transfer';

    const transferReference = ref('TRF');

    await client.query(
      `INSERT INTO transactions
       (reference, account_id, related_account_id, user_id, type,
        description, amount, direction, balance_after, idempotency_key)
       VALUES ($1, $2, $3, $4, 'transfer_out', $5, $6, 'debit', $7, $8)`,
      [
        transferReference,
        source.id,
        destination.id,
        req.session.userId,
        description,
        value.amount,
        sourceUpdate.rows[0].current_balance,
        value.idempotencyKey || null
      ]
    );

    await client.query(
      `INSERT INTO transactions
       (reference, account_id, related_account_id, user_id, type,
        description, amount, direction, balance_after)
       VALUES ($1, $2, $3, $4, 'transfer_in', $5, $6, 'credit', $7)`,
      [
        ref('TRF'),
        destination.id,
        source.id,
        destination.user_id,
        description,
        value.amount,
        destinationUpdate.rows[0].current_balance
      ]
    );

    await client.query('COMMIT');

    res.json({
      success: true,
      reference: transferReference,
      amount: money(value.amount),
      message: 'Simulated transfer completed.',
      accounts: await getAccounts(req.session.userId)
    });
  } catch (error) {
    if (client) {
      try {
        await client.query('ROLLBACK');
      } catch {}
    }

    next(error);
  } finally {
    if (client) client.release();
  }
});

// Support tickets
app.get('/api/support', requireAuth, async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `SELECT t.*,
        (SELECT COUNT(*)::int
         FROM support_messages m
         WHERE m.ticket_id = t.id) AS message_count
       FROM support_tickets t
       WHERE t.user_id = $1
       ORDER BY t.updated_at DESC`,
      [req.session.userId]
    );

    res.json({ tickets: rows });
  } catch (error) {
    next(error);
  }
});

app.post('/api/support', requireAuth, async (req, res, next) => {
  const parsed = z
    .object({
      subject: text(120),
      message: text(2000)
    })
    .safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      error: 'Enter a subject and message.'
    });
  }

  let client;

  try {
    client = await pool.connect();
    await client.query('BEGIN');

    const ticket = await client.query(
      `INSERT INTO support_tickets(reference, user_id, subject)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [ref('TKT'), req.session.userId, parsed.data.subject]
    );

    await client.query(
      `INSERT INTO support_messages(ticket_id, sender_id, message)
       VALUES ($1, $2, $3)`,
      [ticket.rows[0].id, req.session.userId, parsed.data.message]
    );

    await client.query('COMMIT');

    res.status(201).json({ ticket: ticket.rows[0] });
  } catch (error) {
    if (client) {
      try {
        await client.query('ROLLBACK');
      } catch {}
    }

    next(error);
  } finally {
    if (client) client.release();
  }
});

app.get(
  '/api/support/:id/messages',
  requireAuth,
  async (req, res, next) => {
    try {
      const own = await pool.query(
        'SELECT id FROM support_tickets WHERE id = $1 AND user_id = $2',
        [req.params.id, req.session.userId]
      );

      if (!own.rowCount && req.session.role !== 'admin') {
        return res.status(404).json({
          error: 'Ticket not found.'
        });
      }

      const { rows } = await pool.query(
        `SELECT m.id, m.message, m.created_at,
                u.first_name, u.last_name, u.role
         FROM support_messages m
         JOIN users u ON u.id = m.sender_id
         WHERE m.ticket_id = $1
         ORDER BY m.created_at`,
        [req.params.id]
      );

      res.json({ messages: rows });
    } catch (error) {
      next(error);
    }
  }
);

app.post(
  '/api/support/:id/messages',
  requireAuth,
  async (req, res, next) => {
    const parsed = z
      .object({ message: text(2000) })
      .safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: 'Enter a message.'
      });
    }

    let client;

    try {
      client = await pool.connect();
      await client.query('BEGIN');

      const ticket = await client.query(
        'SELECT * FROM support_tickets WHERE id = $1 FOR UPDATE',
        [req.params.id]
      );

      if (
        !ticket.rowCount ||
        (req.session.role !== 'admin' &&
          String(ticket.rows[0].user_id) !== String(req.session.userId))
      ) {
        await client.query('ROLLBACK');

        return res.status(404).json({
          error: 'Ticket not found.'
        });
      }

      await client.query(
        `INSERT INTO support_messages(ticket_id, sender_id, message)
         VALUES ($1, $2, $3)`,
        [req.params.id, req.session.userId, parsed.data.message]
      );

      await client.query(
        `UPDATE support_tickets
         SET updated_at = NOW(),
             status = CASE
               WHEN $2 = 'admin' AND status = 'open'
               THEN 'in_progress'
               ELSE status
             END
         WHERE id = $1`,
        [req.params.id, req.session.role]
      );

      await client.query('COMMIT');
      res.status(201).json({ success: true });
    } catch (error) {
      if (client) {
        try {
          await client.query('ROLLBACK');
        } catch {}
      }

      next(error);
    } finally {
      if (client) client.release();
    }
  }
);

// Administrator endpoints
app.get(
  '/api/admin/overview',
  requireAuth,
  requireAdmin,
  async (_req, res, next) => {
    try {
      const [users, accounts, transactions, tickets, logs] =
        await Promise.all([
          pool.query(
            "SELECT COUNT(*)::int AS count FROM users WHERE role = 'customer'"
          ),
          pool.query('SELECT COUNT(*)::int AS count FROM bank_accounts'),
          pool.query('SELECT COUNT(*)::int AS count FROM transactions'),
          pool.query(
            "SELECT COUNT(*)::int AS count FROM support_tickets WHERE status <> 'closed'"
          ),
          pool.query(
            `SELECT id, actor_id, action, target_id, details, created_at
             FROM audit_logs
             ORDER BY created_at DESC
             LIMIT 50`
          )
        ]);

      res.json({
        customers: users.rows[0].count,
        accounts: accounts.rows[0].count,
        transactions: transactions.rows[0].count,
        openTickets: tickets.rows[0].count,
        auditLogs: logs.rows
      });
    } catch (error) {
      next(error);
    }
  }
);

app.get(
  '/api/admin/customers',
  requireAuth,
  requireAdmin,
  async (req, res, next) => {
    try {
      const search = String(req.query.search || '').slice(0, 100);

      const { rows } = await pool.query(
        `SELECT id, email, first_name, last_name, phone, status, created_at
         FROM users
         WHERE role = 'customer'
           AND (
             $1 = ''
             OR email ILIKE $2
             OR first_name ILIKE $2
             OR last_name ILIKE $2
           )
         ORDER BY created_at DESC
         LIMIT 200`,
        [search, `%${search}%`]
      );

      res.json({ customers: rows });
    } catch (error) {
      next(error);
    }
  }
);

app.post(
  '/api/admin/customers',
  requireAuth,
  requireAdmin,
  async (req, res, next) => {
    const parsed = z
      .object({
        email: emailSchema,
        password: z.string().min(12).max(128),
        firstName: text(80),
        lastName: text(80)
      })
      .safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error:
          'Provide valid customer details and a password of at least 12 characters.'
      });
    }

    let client;

    try {
      client = await pool.connect();
      await client.query('BEGIN');

      const hash = await bcrypt.hash(parsed.data.password, 12);

      const user = await client.query(
        `INSERT INTO users(email, password_hash, first_name, last_name)
         VALUES ($1, $2, $3, $4)
         RETURNING id, email, first_name, last_name, status, created_at`,
        [
          parsed.data.email,
          hash,
          parsed.data.firstName,
          parsed.data.lastName
        ]
      );

      await createAccounts(client, user.rows[0].id);

      await client.query(
        `INSERT INTO audit_logs(actor_id, action, target_id, details)
         VALUES ($1, $2, $3, $4)`,
        [
          req.session.userId,
          'customer.created',
          user.rows[0].id,
          JSON.stringify({ email: parsed.data.email })
        ]
      );

      await client.query('COMMIT');

      res.status(201).json({ customer: user.rows[0] });
    } catch (error) {
      if (client) {
        try {
          await client.query('ROLLBACK');
        } catch {}
      }

      if (error.code === '23505') {
        return res.status(409).json({
          error: 'Email already exists.'
        });
      }

      next(error);
    } finally {
      if (client) client.release();
    }
  }
);

app.patch(
  '/api/admin/customers/:id/status',
  requireAuth,
  requireAdmin,
  async (req, res, next) => {
    const parsed = z
      .object({ status: z.enum(['active', 'inactive']) })
      .safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: 'Invalid account status.'
      });
    }

    try {
      const { rows } = await pool.query(
        `UPDATE users
         SET status = $2, updated_at = NOW()
         WHERE id = $1 AND role = 'customer'
         RETURNING id, email, status`,
        [req.params.id, parsed.data.status]
      );

      if (!rows.length) {
        return res.status(404).json({
          error: 'Customer not found.'
        });
      }

      await audit(req.session.userId, 'customer.status_changed', req.params.id, {
        status: parsed.data.status
      });

      res.json({ customer: rows[0] });
    } catch (error) {
      next(error);
    }
  }
);

app.patch(
  '/api/admin/customers/:id/password',
  requireAuth,
  requireAdmin,
  async (req, res, next) => {
    const parsed = z
      .object({ password: z.string().min(12).max(128) })
      .safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: 'New password must be at least 12 characters.'
      });
    }

    try {
      const hash = await bcrypt.hash(parsed.data.password, 12);

      const { rows } = await pool.query(
        `UPDATE users
         SET password_hash = $2, updated_at = NOW()
         WHERE id = $1 AND role = 'customer'
         RETURNING id, email`,
        [req.params.id, hash]
      );

      if (!rows.length) {
        return res.status(404).json({
          error: 'Customer not found.'
        });
      }

      await audit(req.session.userId, 'customer.password_reset', req.params.id, {
        email: rows[0].email
      });

      res.json({
        success: true,
        message:
          'Customer password reset. Share the new password with the customer through a secure channel.'
      });
    } catch (error) {
      next(error);
    }
  }
);

app.post(
  '/api/admin/customers/:id/adjustments',
  requireAuth,
  requireAdmin,
  async (req, res, next) => {
    const parsed = z
      .object({
        accountId: z.string().uuid(),
        amount: amountSchema,
        direction: z.enum(['credit', 'debit']),
        description: z.string().trim().max(160).optional()
      })
      .safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: 'Provide a valid account, positive amount, and adjustment direction.'
      });
    }

    let client;

    try {
      client = await pool.connect();
      await client.query('BEGIN');

      const account = await client.query(
        `SELECT * FROM bank_accounts
         WHERE id = $1 AND user_id = $2
         FOR UPDATE`,
        [parsed.data.accountId, req.params.id]
      );

      if (!account.rowCount) {
        await client.query('ROLLBACK');

        return res.status(404).json({
          error: 'Customer account not found.'
        });
      }

      const current = Number(account.rows[0].current_balance);

      if (parsed.data.direction === 'debit' && current < parsed.data.amount) {
        await client.query('ROLLBACK');

        return res.status(400).json({
          error: 'Adjustment would make the account balance negative.'
        });
      }

      const delta =
        parsed.data.direction === 'credit'
          ? parsed.data.amount
          : -parsed.data.amount;

      const updated = await client.query(
        `UPDATE bank_accounts
         SET current_balance = current_balance + $2,
             available_balance = available_balance + $2
         WHERE id = $1
         RETURNING current_balance`,
        [parsed.data.accountId, delta]
      );

      const transaction = await client.query(
        `INSERT INTO transactions
         (reference, account_id, user_id, type, description, amount,
          direction, balance_after)
         VALUES ($1, $2, $3, 'admin_adjustment', $4, $5, $6, $7)
         RETURNING reference`,
        [
          ref('ADJ'),
          parsed.data.accountId,
          req.params.id,
          parsed.data.description || 'Administrator simulated balance adjustment',
          parsed.data.amount,
          parsed.data.direction,
          updated.rows[0].current_balance
        ]
      );

      await client.query(
        `INSERT INTO audit_logs(actor_id, action, target_id, details)
         VALUES ($1, $2, $3, $4)`,
        [
          req.session.userId,
          'account.balance_adjusted',
          parsed.data.accountId,
          JSON.stringify({
            customerId: req.params.id,
            direction: parsed.data.direction,
            amount: money(parsed.data.amount),
            reference: transaction.rows[0].reference
          })
        ]
      );

      await client.query('COMMIT');

      res.json({
        success: true,
        reference: transaction.rows[0].reference,
        balance: money(updated.rows[0].current_balance)
      });
    } catch (error) {
      if (client) {
        try {
          await client.query('ROLLBACK');
        } catch {}
      }

      next(error);
    } finally {
      if (client) client.release();
    }
  }
);

app.get(
  '/api/admin/tickets',
  requireAuth,
  requireAdmin,
  async (_req, res, next) => {
    try {
      const { rows } = await pool.query(
        `SELECT t.*, u.email, u.first_name, u.last_name
         FROM support_tickets t
         JOIN users u ON u.id = t.user_id
         ORDER BY t.updated_at DESC
         LIMIT 200`
      );

      res.json({ tickets: rows });
    } catch (error) {
      next(error);
    }
  }
);

app.patch(
  '/api/admin/tickets/:id',
  requireAuth,
  requireAdmin,
  async (req, res, next) => {
    const parsed = z
      .object({ status: z.enum(['open', 'in_progress', 'closed']) })
      .safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: 'Invalid ticket status.'
      });
    }

    try {
      const { rows } = await pool.query(
        `UPDATE support_tickets
         SET status = $2, updated_at = NOW()
         WHERE id = $1
         RETURNING *`,
        [req.params.id, parsed.data.status]
      );

      if (!rows.length) {
        return res.status(404).json({
          error: 'Ticket not found.'
        });
      }

      await audit(req.session.userId, 'support.status_changed', req.params.id, {
        status: parsed.data.status
      });

      res.json({ ticket: rows[0] });
    } catch (error) {
      next(error);
    }
  }
);

app.get(
  '/api/admin/customers/:id/accounts',
  requireAuth,
  requireAdmin,
  async (req, res, next) => {
    try {
      const { rows } = await pool.query(
        `SELECT id, account_type, account_number, current_balance,
                available_balance, status
         FROM bank_accounts
         WHERE user_id = $1
         ORDER BY account_type`,
        [req.params.id]
      );

      res.json({
        accounts: rows.map(account => ({
          ...account,
          current_balance: money(account.current_balance),
          available_balance: money(account.available_balance)
        }))
      });
    } catch (error) {
      next(error);
    }
  }
);

// Unknown API endpoints should return JSON.
app.use('/api', (_req, res) => {
  res.status(404).json({
    error: 'API endpoint not found.'
  });
});

// Express 5-compatible fallback for frontend routes.
// API requests have already been handled above.
app.get('/{*path}', (req, res, next) => {
  res.sendFile(path.join(__dirname, 'index.html'), error => {
    if (error) next(error);
  });
});

// Central error handler
app.use((error, req, res, _next) => {
  console.error('Request failed:', error.message);

  if (res.headersSent) return;

  res.status(500).json({
    error: production
      ? 'Something went wrong. Please try again.'
      : error.message
  });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Harborline Banking Simulator running on port ${PORT}`);
  });
}

module.exports = {
  app,
  amountSchema
};
