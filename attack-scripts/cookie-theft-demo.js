const axios = require("axios");

const targetUrl = "http://localhost:3000/login";
const email = process.argv[2] || 'analyst@authx.com';
const password = process.argv[3] || 'Password123';

(async () => {
  try {
    const response = await axios.post(
      targetUrl,
      { email, password },
      { validateStatus: () => true }
    );

    if (response.status === 200) {
      console.log("[SUCCESS] Login endpoint accepted credentials.");
      console.log("Set-Cookie present:", Boolean(response.headers["set-cookie"]));
    } else {
      console.log("[FAIL] Login failed with status:", response.status);
    }
  } catch (err) {
    console.log("[ERROR]", err.message);
  }
})();