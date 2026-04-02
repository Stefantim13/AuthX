const fs = require('fs');
const path = require('path');
const db = require('./connection');

const schemaPath = path.join(__dirname, '../../data/schema.sql');

function initDatabase() {
  const schema = fs.readFileSync(schemaPath, 'utf8');
  db.exec(schema);
  console.log('Database initialized successfully.');
}

initDatabase();
