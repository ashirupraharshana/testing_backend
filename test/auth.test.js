import test from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { createApp } from '../src/app.js';
import { validate } from '../src/validation.js';
const secret = 'test-only-secret-that-is-over-32-characters';
const origins = ['http://localhost:5173'];
// In-memory SQL adapter: tests API behavior, not MySQL server compatibility.
function fixture() {
  const users = [];
  const pool = {
    async query() { return [[{ value: 1 }]]; },
    async execute(sql, params) {
      if (sql.startsWith('INSERT')) {
        if (users.some(u => u.email === params[1])) { const e = new Error(); e.code = 'ER_DUP_ENTRY'; throw e; }
        users.push({ id: users.length + 1, username: params[0], email: params[1], phone: params[2], password_hash: params[3], created_at: new Date().toISOString() });
        return [{ insertId: users.length }];
      }
      return [users.filter(u => sql.includes('WHERE email') ? u.email === params[0] : String(u.id) === String(params[0]))];
    }
  };
  return { app: createApp({ pool, secret, origins }), users };
}
const account = { username: 'ash_iru', email: 'Ash@Example.com', phone: '0771234567', password: 'Testpass123' };
test('register, duplicate, wrong password, login and protected profile', async () => {
  const { app, users } = fixture();
  await request(app).post('/api/auth/register').send(account).expect(201);
  assert.equal(users[0].email, 'ash@example.com');
  assert.notEqual(users[0].password_hash, account.password);
  await request(app).post('/api/auth/register').send(account).expect(409);
  await request(app).post('/api/auth/login').send({ email: account.email, password: 'wrong' }).expect(401);
  const login = await request(app).post('/api/auth/login').send(account).expect(200);
  assert.ok(login.body.token);
  assert.equal(login.body.user.password_hash, undefined);
  const me = await request(app).get('/api/users/me').set('Authorization', `Bearer ${login.body.token}`).expect(200);
  assert.equal(me.body.user.phone, '0771234567');
  assert.equal(me.body.user.password_hash, undefined);
  await request(app).get('/api/users/me').expect(401);
  await request(app).get('/api/users/me').set('Authorization', 'Bearer broken').expect(401);
  const expired = jwt.sign({}, secret, { subject: '1', expiresIn: -1, issuer: 'auth-demo-api', audience: 'auth-demo-web' });
  await request(app).get('/api/users/me').set('Authorization', `Bearer ${expired}`).expect(401);
});
test('validation catches malformed input and preserves leading phone zero', async () => {
  const { app } = fixture();
  const invalid = await request(app).post('/api/auth/register').send({ username: 'a', email: 'bad', phone: '077 123456', password: 'short' }).expect(400);
  assert.equal(Object.keys(invalid.body.errors).length, 4);
  assert.equal(validate(account, true).values.phone, '0771234567');
  await request(app).post('/api/auth/register').send({ email: {}, password: [] }).expect(400);
  await request(app).post('/api/auth/login').set('Content-Type', 'application/json').send('{').expect(400);
});
test('CORS, health, database downtime and unknown paths', async () => {
  const { app } = fixture();
  const healthy = await request(app).get('/api/health').set('Origin', origins[0]).expect(200);
  assert.equal(healthy.headers['access-control-allow-origin'], origins[0]);
  await request(app).get('/api/health').set('Origin', 'https://untrusted.example').expect(403);
  await request(app).get('/not-found').expect(404);
  const broken = createApp({ pool: { async query() { throw new Error('offline'); } }, secret, origins });
  await request(broken).get('/api/health').expect(503);
});
test('repeated authentication requests are rate limited', async () => {
  const { app } = fixture();
  for (let i = 0; i < 30; i++) await request(app).post('/api/auth/login').send({}).expect(400);
  await request(app).post('/api/auth/login').send({}).expect(429);
});
