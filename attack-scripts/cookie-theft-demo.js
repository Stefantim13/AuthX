const axios = require('axios');

const targetUrl = 'http://localhost:3000/login';
const email = 'analyst@authx.com';
const password = 'HackedPassword123';

(async () => {
  try {
  // Login to obtain the session cookie
    const response = await axios.post(targetUrl, { email, password }, { withCredentials: true });
    const setCookie = response.headers['set-cookie'];
    if (setCookie) {
  console.log('[SUCCESS] Session cookie obtained:');
  console.log(setCookie[0]);
    } else {
  console.log('[FAIL] No session cookie received.');
    }
  } catch (err) {
    console.log('[ERROR]', err.message);
  }
})();
