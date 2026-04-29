const db = require('./connection');
const { hashPasswordSync } = require('../lib/passwords');

function seedDatabase() {
  const insertUser = db.prepare(`
    INSERT INTO users (email, password_hash, role, locked)
    VALUES (?, ?, ?, ?)
  `);

  const insertTicket = db.prepare(`
    INSERT INTO tickets (title, description, severity, status, owner_id)
    VALUES (?, ?, ?, ?, ?)
  `);

  const insertAuditLog = db.prepare(`
    INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address)
    VALUES (?, ?, ?, ?, ?)
  `);

  const seed = db.transaction(() => {
    // Clean the tables
    db.prepare('DELETE FROM password_reset_tokens').run();
    db.prepare('DELETE FROM audit_logs').run();
    db.prepare('DELETE FROM tickets').run();
    db.prepare('DELETE FROM users').run();

    const analyst = insertUser.run(
      'analyst@authx.com',
      hashPasswordSync('Password123#Analyst'),
      'ANALYST',
      0
    );

    const manager = insertUser.run(
      'manager@authx.com',
      hashPasswordSync('Password123#Manager'),
      'MANAGER',
      0
    );

    insertTicket.run(
      'Cannot login to VPN',
      'User reports repeated login failure on VPN portal.',
      'HIGH',
      'OPEN',
      analyst.lastInsertRowid
    );

    insertTicket.run(
      'Reset corporate email password',
      'Password reset requested by user after suspicious activity.',
      'MED',
      'IN_PROGRESS',
      analyst.lastInsertRowid
    );

    insertTicket.run(
      'Review failed logins',
      'Manager should review repeated failed login attempts.',
      'LOW',
      'OPEN',
      manager.lastInsertRowid
    );

    insertAuditLog.run(
      analyst.lastInsertRowid,
      'seed_user_created',
      'users',
      analyst.lastInsertRowid,
      '127.0.0.1'
    );

    insertAuditLog.run(
      manager.lastInsertRowid,
      'seed_user_created',
      'users',
      manager.lastInsertRowid,
      '127.0.0.1'
    );

    insertAuditLog.run(
      analyst.lastInsertRowid,
      'seed_ticket_created',
      'tickets',
      1,
      '127.0.0.1'
    );
  });

  seed();
  console.log('Database seeded successfully.');
}

if (require.main === module) {
  seedDatabase();
}

module.exports = seedDatabase;
