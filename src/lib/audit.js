const db = require('../db/connection');

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return String(forwarded).split(',')[0].trim();
  }

  return req.ip || req.socket?.remoteAddress || 'unknown';
}

function writeAuditLog({
  userId = null,
  action,
  resource,
  resourceId = null,
  ipAddress = 'unknown'
}) {
  db.prepare(`
    INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address)
    VALUES (?, ?, ?, ?, ?)
  `).run(userId, action, resource, resourceId, ipAddress);
}

module.exports = {
  getClientIp,
  writeAuditLog
};
