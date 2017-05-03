'use strict';
const tokenFactory = require('../services/tokenFactory');

const models = require('../models/index');

const expirationIgnorePaths = ['/auth/token'];

/**
 * The middleware to authorize requests that should be protected by a login
 * @param  {object}   req  The request object provided by the Express router
 * @param  {object}   res  The response object provided by the Express router
 * @param  {Function} next The callback to move the operation forward
 */
const userIdentifier = (req, res, next) => {
  try {
    // TODO: Simplify the RegExp
    const authorizationHeader = req.header('Authorization') || '';
    const token = authorizationHeader
      .match(/[A-Za-z0-9\-_~\+\/]*\.[A-Za-z0-9\-_~\+\/]*\.[A-Za-z0-9\-_~\+\/]*/)[0];
      const ignoreExpiration = expirationIgnorePaths.indexOf(req.originalUrl) !== -1;
      const decoded = tokenFactory.verifyAuthToken(token, ignoreExpiration);

    models
      .User
      .find({
        where: {
          id: decoded.user.id,
        },
      })
      .then((user) => {
        req.user = user;
        next();
      });
  } catch (e) {
    next();
  }
};

module.exports = userIdentifier;
