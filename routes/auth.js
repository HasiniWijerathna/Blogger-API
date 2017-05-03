'use strict';
const express = require('express');
const router = express.Router(); // eslint-disable-line

const models = require('../models/index');
const config = require('../config');
const authRequired = require('../middlewares/authRequired');
const tokenFactory = require('../services/tokenFactory');
const errorFactory = require('../services/errorFactory');
const userService = require('../services/userService');

/**
 * Finds the user with the given credentials
 * @param  {String} username The username
 * @param  {String} password The password
 * @return {Promise}         Flag specifying whether the user exists
 */
const findUser = (username, password) => {
  return models
    .User
    .find({
      where: {
        username,
        password: userService.getPasswordHash(password),
      },
      attributes: {
        exclude: ['password'],
      },
    });
};

/**
 * Creates the response object
 * @param  {object} user User object
 * @return {object}      Response object
 */
const prepareResponse = (user) => {
  const nowTime = Date.now();
  const expiration = nowTime + (config.authToken.expiresIn * 1000); // Add expiration time and convert to milliseconds
  const tokenData = {
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
    },
  };
  return {
    expiration,
    user,
    token: tokenFactory.issueAuthToken(tokenData),
  };
};
/**
 * Refresh the token
 */
router.get('/token', authRequired, (req, res) => {
    res.send(prepareResponse(req.user));
});
/**
 * Registering the '/login' route
 */
router.post('/login', (req, res, next) => {
  findUser(req.body.username, req.body.password)
    .then((user) => {
      if (user) {
        res.send(prepareResponse(user));
      } else {
        throw errorFactory.unauthorized(req);
      }
    })
    .catch(next);
    // .catch((error) => {
    //   next(error);
    // });
});

/**
 * Registering the '/register' route
 */
router.post('/register', (req, res, next) => {
  const user = {
    username: req.body.username,
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
  };

  if (userService.validateUser(user)) {
    user.password = userService.getPasswordHash(req.body.password);
    models
      .User
      .find({
        where: {
          email: req.body.email,
        },
      })
      .then((existingUser) => {
        let promise = null;

        if (existingUser) {
          throw errorFactory.badRequest(req, 'User already exists');
        } else {
          promise = models.User.create(user);
        }
        return promise;
      })
      .then((createdUser) => {
        const tokenData = {
          user: {
            id: createdUser.id,
            username: createdUser.username,
            email: createdUser.email,
          },
        };
        const nowTime = Date.now();
        const expiration = nowTime + (config.authToken.expiresIn * 1000);
        res.json({
          expiration,
          user: createdUser,
          message: `Welcome ${createdUser.name}`,
          token: tokenFactory.issueAuthToken(tokenData),
        });
      })
      .catch(next);
  } else {
    next(errorFactory.badRequest(req, 'Validation error'));
  }
});

module.exports = router;
