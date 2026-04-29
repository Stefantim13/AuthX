const app = require('../src/app');
const db = require('../src/db/connection');
const inject = require('light-my-request');
const initDatabase = require('../src/db/init');
const seedDatabase = require('../src/db/seed');

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

async function main() {
  initDatabase();
  seedDatabase();

  let cookieJar = '';

  async function request(method, url, payload) {
    const headers = {
      accept: 'application/json'
    };

    if (cookieJar) {
      headers.cookie = cookieJar;
    }

    if (payload) {
      headers['content-type'] = 'application/json';
    }

    const response = await inject(app, {
      method,
      url,
      headers,
      payload: payload ? JSON.stringify(payload) : undefined
    });

    const setCookie = response.headers['set-cookie'];
    if (setCookie) {
      const normalizedCookie = Array.isArray(setCookie) ? setCookie[0] : setCookie;
      cookieJar = normalizedCookie.split(';')[0];
    }

    const body = response.body ? JSON.parse(response.body) : {};
    return {
      status: response.statusCode,
      headers: response.headers,
      body
    };
  }

  let result = await request('POST', '/register', {
    email: 'weak@authx.com',
    password: '12345',
    role: 'ANALYST'
  });
  assert(result.status === 400, 'Weak password registration should fail');

  result = await request('POST', '/login', {
    email: 'ghost@authx.com',
    password: 'WrongPass1!'
  });
  assert(result.status === 401, 'Unknown user should receive 401');
  assert(result.body.message === 'Invalid credentials', 'Unknown user message must be generic');

  result = await request('POST', '/login', {
    email: 'analyst@authx.com',
    password: 'WrongPass1!'
  });
  assert(result.status === 401, 'Wrong password should receive 401');
  assert(result.body.message === 'Invalid credentials', 'Wrong password message must be generic');

  for (let attempt = 0; attempt < 4; attempt += 1) {
    result = await request('POST', '/login', {
      email: 'analyst@authx.com',
      password: 'WrongPass1!'
    });
  }
  assert(result.status === 429, 'Account should be temporarily locked after repeated failures');

  db.prepare(`
    UPDATE users
    SET failed_login_attempts = 0,
        locked = 0,
        locked_until = NULL,
        last_failed_login_at = NULL
    WHERE email = ?
  `).run('analyst@authx.com');

  result = await request('POST', '/login', {
    email: 'analyst@authx.com',
    password: 'Password123#Analyst'
  });
  assert(result.status === 200, 'Valid login should succeed');

  const cookieHeader = result.headers['set-cookie']?.[0] || result.headers['set-cookie'] || '';
  assert(cookieHeader.includes('HttpOnly'), 'Session cookie should be HttpOnly');
  assert(cookieHeader.includes('SameSite=Lax'), 'Session cookie should set SameSite=Lax');

  result = await request('GET', '/me');
  assert(result.status === 200, 'Authenticated session should access /me');

  result = await request('GET', '/tickets/3');
  assert(result.status === 404, 'Analyst should not access manager ticket');

  result = await request('POST', '/forgot-password', {
    email: 'analyst@authx.com'
  });
  assert(result.status === 200, 'Forgot password should respond successfully');
  assert(result.body.resetToken, 'Forgot password should return demo token for local testing');

  const resetToken = result.body.resetToken;
  result = await request('POST', '/reset-password', {
    token: resetToken,
    newPassword: 'UpdatedPass1!'
  });
  assert(result.status === 200, 'Password reset should succeed with fresh token');

  result = await request('POST', '/reset-password', {
    token: resetToken,
    newPassword: 'AnotherPass1!'
  });
  assert(result.status === 400, 'Reset token should be one-time use');

  cookieJar = '';
  result = await request('POST', '/login', {
    email: 'analyst@authx.com',
    password: 'UpdatedPass1!'
  });
  assert(result.status === 200, 'Login should work with new password');

  result = await request('POST', '/logout');
  assert(result.status === 200, 'Logout should succeed');

  result = await request('GET', '/me');
  assert(result.status === 401, 'Destroyed session should no longer access /me');

  console.log('Secure verification completed successfully.');
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
