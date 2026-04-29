const fs = require('fs');
const path = require('path');
const db = require('./connection');

const schemaPath = path.join(__dirname, '../../data/schema.sql');

function initDatabase() {
  db.exec(`
    DROP TABLE IF EXISTS password_reset_tokens;
    DROP TABLE IF EXISTS audit_logs;
    DROP TABLE IF EXISTS tickets;
    DROP TABLE IF EXISTS users;
  `);

  const schema = fs.readFileSync(schemaPath, 'utf8');
  db.exec(schema);
  console.log('Database initialized successfully.');
}

if (require.main === module) {
  initDatabase();
}

module.exports = initDatabase;
