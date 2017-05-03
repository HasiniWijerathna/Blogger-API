'use strict';
const express = require('express');
const router = express.Router(); // eslint-disable-line

const models = require('../models/index');
const errorFactory = require('../services/errorFactory');
const userIdentifier = require('../middlewares/userIdentifier');
const validateInputs = require('../services/validateInputs');
const authRequired = require('../middlewares/authRequired');
const modelDeleteAuthorizer = require('../middlewares/modelDeleteAuthorizer').bind(null, models.Posts, 'postId');

router.get('/', (req, res) => {
  // Return all posts
  models
  .Posts
  .findAll({
    attributes: ['id', 'title', 'content'],
    include: [models.Comments],
    order: [
      ['title', 'ASC'],
    ],
  })
    .then((allPosts) => {
      res.json({
    results: allPosts,
    });
  });
});

router.post('/', userIdentifier, authRequired, (req, res, next) => {
  // Create new post
  const title = req.body.title;
  const content = req.body.content;
  const titleError = validateInputs.validateName(req, title);
  const contentError = validateInputs.validateName(req, content);
  if (titleError || contentError ) {
    next(titleError || contentError);
  } else {
    models
    .Posts
    .create({
      title: req.body.title,
      content: req.body.content,
      BlogId: req.body.blogId,
      UserId: req.user.id,
    })
      .then((newPost) => {
      res.json(newPost);
    });
  }
});

router.get('/:postId', userIdentifier, (req, res, next) => {
  // Return post with ID 'postId'
  models
  .Posts
  .find({
     where: {
       id: req.params.postId,
     },
     include: [models.Comments],
   })
  .then((existingPost) => {
    let promise = null;

    if(existingPost) {
      promise = res.json(existingPost);
    } else {
      throw errorFactory.notFound(req, 'Post does not exist');
    }
    return promise;
  })
  .catch(next);
});

router.put('/:postId', userIdentifier, (req, res, next) => {
  // Update post with ID 'postId'
  models
  .Posts
  .find({
    where: {
      id: req.params.postId,
    },
  })
  .then((post) => {
    let promise = null;

    if (post) {
      promise = post.updateAttributes({
        title: req.body.title,
        content: req.body.content,
      });
    } else {
      throw errorFactory.badRequest(req, 'Post does not exist');
    }

    return promise;
  })
  .then((updatedPost) => {
    res.send(updatedPost);
  })
  .catch(next);
});

router.delete('/:postId', userIdentifier, authRequired, modelDeleteAuthorizer, (req, res, next) => {
  // Delete post with ID 'postId'
  models.Posts.destroy({
    where: {
      id: req.params.postId,
    },
  }).then(function(deletedPost) {
    res.json(deletedPost);
  });
});

module.exports = router;
