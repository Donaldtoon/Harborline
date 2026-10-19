require('dotenv').config();
const fs = require('node:fs');
const path = require('node:path');
const { pool } = require('./db');
(async () => {
  try {
    const sql = fs.readFileSync(path.join(__dirname, '..', 'db', 'migrations', '001_initial.sql'), 'utf8');
    await pool.query(sql);
    console.log('Database migration completed.');
  } catch (err) { console.error('Migration failed:', err.message); process.exitCode = 1; }
  finally { await pool.end(); }
})();
