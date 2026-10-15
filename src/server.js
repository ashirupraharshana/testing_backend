import 'dotenv/config';
import { createPool } from './db.js';
import { createApp } from './app.js';
const secret = process.env.JWT_SECRET || '';
if (secret.length < 32 || secret.startsWith('REPLACE_')) throw new Error('Set JWT_SECRET to a random value of at least 32 characters.');
const origins = (process.env.CLIENT_ORIGINS || 'http://localhost:5173').split(',').map(s => s.trim()).filter(Boolean);
const pool = createPool(process.env);
const app = createApp({ pool, secret, origins, trustProxy: Number(process.env.TRUST_PROXY || 0) });
const port = Number(process.env.PORT || 5000);
const server = app.listen(port, '0.0.0.0', () => console.log(`API listening on port ${port}`));
async function shutdown() { server.close(async () => { await pool.end(); process.exit(0); }); }
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
