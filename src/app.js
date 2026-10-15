import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { rateLimit } from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import { hashPassword, verifyPassword } from './password.js';
import { validate } from './validation.js';
const publicUser = ({ id, username, email, phone, created_at }) => ({ id, username, email, phone, created_at });
export function createApp({ pool, secret, origins, trustProxy = 0 }) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', trustProxy);
  app.use(helmet());
  app.use(cors({ origin(origin, done) {
    if (!origin || origins.includes(origin)) return done(null, true);
    const error = new Error('Origin is not allowed.'); error.status = 403; done(error);
  }}));
  app.use(express.json({ limit: '16kb' }));
  app.get('/', (_req, res) => res.json({ message: 'Auth demo API is running.' }));
  app.get('/api/health', async (_req, res) => {
    try { await pool.query('SELECT 1'); res.json({ status: 'ok', database: 'connected' }); }
    catch { res.status(503).json({ status: 'error', database: 'unavailable' }); }
  });
  app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 30,
    standardHeaders: 'draft-8', legacyHeaders: false,
    message: { message: 'Too many attempts. Try again in 15 minutes.' }
  }));
  app.post('/api/auth/register', async (req, res) => {
    const { errors, values } = validate(req.body, true);
    if (Object.keys(errors).length) return res.status(400).json({ message: 'Please check your details.', errors });
    const { username, email, phone, password } = values;
    try {
      const passwordHash = await hashPassword(password);
      await pool.execute('INSERT INTO users (username, email, phone, password_hash) VALUES (?, ?, ?, ?)', [username, email, phone, passwordHash]);
      return res.status(201).json({ message: 'Account created. You can now log in.' });
    } catch (error) {
      if (error.code === 'ER_DUP_ENTRY') return res.status(409).json({ message: 'This email is already registered.' });
      throw error;
    }
  });
  app.post('/api/auth/login', async (req, res) => {
    const { errors, values } = validate(req.body);
    if (Object.keys(errors).length) return res.status(400).json({ message: 'Please check your details.', errors });
    const [rows] = await pool.execute('SELECT * FROM users WHERE email = ? LIMIT 1', [values.email]);
    const user = rows[0];
    if (!user || !(await verifyPassword(values.password, user.password_hash))) return res.status(401).json({ message: 'Invalid email or password.' });
    const token = jwt.sign({}, secret, { algorithm: 'HS256', subject: String(user.id), expiresIn: '1h', issuer: 'auth-demo-api', audience: 'auth-demo-web' });
    res.json({ message: 'Login successful.', token, user: publicUser(user) });
  });
  app.get('/api/users/me', async (req, res) => {
    const header = req.headers.authorization || '';
    if (!header.startsWith('Bearer ')) return res.status(401).json({ message: 'Please log in.' });
    let payload;
    try { payload = jwt.verify(header.slice(7), secret, { algorithms: ['HS256'], issuer: 'auth-demo-api', audience: 'auth-demo-web' }); }
    catch { return res.status(401).json({ message: 'Session expired. Please log in again.' }); }
    const [rows] = await pool.execute('SELECT id, username, email, phone, created_at FROM users WHERE id = ? LIMIT 1', [payload.sub]);
    if (!rows[0]) return res.status(401).json({ message: 'Account no longer exists.' });
    res.json({ user: publicUser(rows[0]) });
  });
  app.use((_req, res) => res.status(404).json({ message: 'Endpoint not found.' }));
  app.use((error, _req, res, _next) => {
    if (error.type === 'entity.parse.failed') return res.status(400).json({ message: 'Invalid JSON body.' });
    if (error.type === 'entity.too.large') return res.status(413).json({ message: 'Request body too large.' });
    if (error.status === 403) return res.status(403).json({ message: error.message });
    console.error('Request failed:', error.code || error.name);
    res.status(500).json({ message: 'Server error. Check backend logs and database connection.' });
  });
  return app;
}
