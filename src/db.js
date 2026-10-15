import mysql from 'mysql2/promise';
import { readFileSync } from 'node:fs';
export function createPool(env) {
  for (const key of ['DB_HOST', 'DB_USER', 'DB_NAME']) {
    if (!env[key]) throw new Error(`Missing ${key}. Copy .env.example to .env and configure it.`);
  }
  return mysql.createPool({
    host: env.DB_HOST, port: Number(env.DB_PORT || 3306),
    user: env.DB_USER, password: env.DB_PASSWORD || '', database: env.DB_NAME,
    waitForConnections: true, connectionLimit: 5, queueLimit: 20, connectTimeout: 10000,
    ...(env.DB_SSL === 'true' ? { ssl: { rejectUnauthorized: true,
      ...(env.DB_SSL_CA_FILE ? { ca: readFileSync(env.DB_SSL_CA_FILE, 'utf8') } : {})
    }} : {})
  });
}
