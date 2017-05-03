'use strict';
const express = require('express');
const router = express.Router(); // eslint-disable-line
// const policy = require('s3-policy');
// const AWS = require('aws-sdk');
const uuidV4 = require('uuid/v4');
const crypto = require('crypto');

const config = require('../config');

const accessKey = process.env.AWS_ACCESS_KEY_ID;
const secretKey = process.env.AWS_SECRET_ACCESS_KEY;
const length = 5000000;
const url = 'https://' + config.bucket + '.s3.amazonaws.com';
const key = uuidV4();

router.get('/policy', (req, res, next) => {
  const expires = new Date(Date.now() + 60000);
  const acl = 'public-read';

  // Create the policy JSON
  const policyObject = {
    expiration: expires,
    // Removed the commented out elements to get the thing working.
    // Add them as required later
    conditions: [
      {bucket: config.bucket},
      {acl},
      // ['starts-with', '$key', ''],
      // ['starts-with', '$Content-Type', ''],
      // ['starts-with', '$name', ''],
      ['content-length-range', '0', '524288000'],
    ],
  };

  // Encoding the policy
  const stringPolicy = JSON.stringify(policyObject);
  const policy = Buffer(stringPolicy, 'utf-8').toString('base64'); // eslint-disable-line

  // Generate the signature
  const signature = crypto.createHmac('sha1', secretKey)
    .update(new Buffer(policy, 'utf-8')).digest('base64');

  // // Format the output
  // const credentials = {
  //   AWSAccessKeyId: accessKey,
  //   policy: base64Policy,
  //   signature,
  //   acl,
  //   key,
  // };

  // const filePolicy = policy({
  //   secret: secretKey,
  //   length: length,
  //   bucket: config.bucket,
  //   key,
  //   expires,
  //   acl,
  // });

  res.send({
    policy,
    signature,
    accessKey,
    url,
    expires: parseInt(expires.getTime()/1000),
    key,
    acl,
    signatureVersion: 'v4',
  });

  // res.json({
  //   url,
  //   awsAccessKeyId: accessKey,
  //   bucket: config.bucket,
  //   expires,
  //   credentials,
  // });
});


module.exports = router;
