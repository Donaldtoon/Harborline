const { Pool } = require('pg');
const connectionString = process.env.DATABASE_URL;
if (!connectionString) throw new Error('DATABASE_URL is required. Copy .env.example to .env and configure PostgreSQL.');
const pool = new Pool({ connectionString, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false });
pool.on('error', err => console.error('Unexpected PostgreSQL pool error:', err.message));
module.exports = { pool };
