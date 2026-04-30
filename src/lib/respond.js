function isJsonRequest(req) {
  const contentType = req.headers['content-type'] || '';
  const accept = req.headers.accept || '';
  return contentType.includes('application/json') || accept.includes('application/json');
}

function respond(req, res, statusCode, payload, viewName, viewModel = {}) {
  if (isJsonRequest(req)) {
    return res.status(statusCode).json(payload);
  }

  if (statusCode >= 300 && statusCode < 400 && payload.redirectTo) {
    return res.redirect(payload.redirectTo);
  }

  return res.status(statusCode).render(viewName, {
    error: null,
    success: null,
    resetToken: null,
    ...viewModel
  });
}

module.exports = {
  isJsonRequest,
  respond
};
