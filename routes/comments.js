'use strict';
const express = require('express');
const router = express.Router(); // eslint-disable-line

const models = require('../models/index');
const errorFactory = require('../services/errorFactory');
const validateInputs = require('../services/validateInputs');
const authRequired = require('../middlewares/authRequired');
const userIdentifier = require('../middlewares/userIdentifier');
const modelDeleteAuthorizer = require('../middlewares/modelDeleteAuthorizer').bind(null, models.Comments, 'commentId');

/* GET all comments listing. */
router.get('/', (req, res) => {
  // Return all Blogs
  models
  .Comments
  .findAll({
    attributes: ['id', 'comment', 'PostId', 'UserId'],
  })
    .then((allComments) => {
    res.json({
      results: allComments,
    });
  });
});

/* Create new comment */
router.post('/', userIdentifier, authRequired, (req, res, next) => {
  const comment = req.body.comment;
  const commentError = validateInputs.validateName(req, comment);
  if (commentError) {
      next(commentError);
  } else {
    models
    .Comments
    .create({
      comment: req.body.comment,
      PostId: req.body.postId,
      UserId: req.user.id,
    })
      .then((newComment) => {
      res.json(newComment);
    });
  }
});
/* Return comment with ID 'commentId' */
router.get('/:commentId', (req, res, next) => {
  models
  .Comments
  .find({
     where: {
       id: req.params.commentId,
     },
   })
   .then((existingComment) => {
     let promise = null;

     if(existingComment) {
       promise = res.json(existingComment);
     } else {
       throw errorFactory.badRequest(req, 'Comment does not exist');
     }
     return promise;
   })
   .catch(next);
});

/* Update comment with ID 'commentId' */
router.put('/:commentId', userIdentifier, authRequired, modelDeleteAuthorizer, (req, res, next) => {
  models
  .Comments
  .find({
    where: {
      id: req.params.commentId,
    },
  })
  .then((comment) => {
    let promise = null;

    if (comment) {
      promise = comment.updateAttributes({
        comment: req.body.comment,
      });
    } else {
      throw errorFactory.badRequest(req, 'Comment does not exist');
    }

    return promise;
  })
  .then((updatedComment) => {
    res.send(updatedComment);
  })
  .catch(next);
});

router.delete('/:commentId', userIdentifier, authRequired, modelDeleteAuthorizer, (req, res, next) => {
  // Delete comment with ID 'commentId'
  models.Comments.destroy({
    where: {
      id: req.params.commentId,
    },
  })
  .then((deletedComment) => {
    // res.json(deletedComment);
    res.json({
      results: true,
    });
  });
});

module.exports = router;
