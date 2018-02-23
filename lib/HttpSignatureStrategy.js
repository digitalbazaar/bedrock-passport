/*
 * Copyright (c) 2013-2016 Digital Bazaar, Inc. All rights reserved.
 */
var _ = require('lodash');
var async = require('async');
var bedrock = require('bedrock');
var brIdentity = require('bedrock-identity');
var brKey = require('bedrock-key');
var httpSignature = require('http-signature');
var jsigs = require('jsonld-signatures');
var passport = require('passport');
var util = require('util');
var BedrockError = bedrock.util.BedrockError;
var didio = require('did-io');
var jsonld = require('jsonld');
var URL = require('url');
var request = require('request');

module.exports = Strategy;

var REQUIRED_HEADERS_OLD = ['request-line', 'host', 'date'];
var REQUIRED_HEADERS = ['(request-target)', 'host', 'date'];

bedrock.events.on('bedrock.init', function() {
  // get configured lib instances
  jsonld = jsonld();
  didio = didio();
  didio.use('jsonld', jsonld);
  jsonld.documentLoader = didio.createDocumentLoader({
    wrap: function(url, callback) {
      return bedrock.jsonld.documentLoader(url, callback);
    },
    baseUrl: bedrock.config.passport.strategies.did.didio.baseUrl
  });
  jsigs = jsigs();
  jsigs.use('jsonld', jsonld);
});

/**
 * Creates a new HttpSignatureStrategy for use with passport.
 */
function Strategy() {
  passport.Strategy.call(this);
  this.name = 'signature';
}
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate a request.
 *
 * @param req the request to authenticate.
 */
Strategy.prototype.authenticate = function(req) {
  var self = this;

  // check that message is signed with the Signature scheme
  // check for 'Authorization: Signature ...'
  var found = false;
  var auth = req.get('Authorization');
  if(auth) {
    var parts = auth.split(' ');
    if(parts && parts.length > 0 && parts[0] === 'Signature') {
      found = true;
    }
  }
  if(!found) {
    // TODO: seems like an invalid use of the passport API, fail is
    // expecting an optional challenge string not an error?
    return self.fail(new BedrockError(
      'Request is not signed.',
      'HttpSignature.NotSigned'));
  }

  async.auto({
    parseRequest: function(callback) {
      var parsed;
      try {
        parsed = httpSignature.parseRequest(req);
      } catch(ex) {
        return callback(new BedrockError(
          'Request signature parse error.',
          'HttpSignature.ParseError',
          null, ex));
      }
      callback(null, parsed);
    },
    checkRequest: ['parseRequest', function(callback, results) {
      var diff = _.difference(
        REQUIRED_HEADERS,
        results.parseRequest.params.headers);
      if(diff.length > 0) {
        // old headers also valid
        diff = _.difference(
          REQUIRED_HEADERS_OLD,
          results.parseRequest.params.headers);
      }
      if(diff.length > 0) {
        return callback(new BedrockError(
          'Missing required headers in HTTP signature.',
          'HttpSignature.MissingHeaders', {
            'public': true,
            httpStatusCode: 400,
            requiredHeaders: REQUIRED_HEADERS
          }));
      }
      callback();
    }],
    getPublicKey: ['checkRequest', function(callback, results) {
      var publicKey = {id: results.parseRequest.keyId};
      brKey.getPublicKey(publicKey, function(err, key) {
        if(err && err.name === 'NotFound') {
          // Retrieve the public key based on the ID's
          // URL scheme when we can't find it in our database.
          return getPublicKey(publicKey.id, function(err, key) {
            callback(err, key);
          });
        }
        return callback(err, key);
      });
    }],
    validatePublicKey: ['getPublicKey', function(callback, results) {
      if(results.getPublicKey.revoked &&
        _timestampBeforeNow(results.getPublicKey.revoked)) {
        return callback(new BedrockError(
          'Public key has been revoked.',
          'HttpSignature.PublicKeyRevocation', {
            'public': true,
            httpStatusCode: 400,
            publicKey: {
              id: results.getPublicKey.id,
              revoked: results.getPublicKey.revoked
            }
          }));
      }
      callback();
    }],
    verify: ['validatePublicKey', function(callback, results) {
      var verified;
      try {
        verified = httpSignature.verifySignature(
          results.parseRequest, results.getPublicKey.publicKeyPem);
      } catch(ex) {
        return callback(new BedrockError(
          'Request signature verify error.',
          'HttpSignature.VerifyError', {cause: ex}));
      }
      if(!verified) {
        return callback(new BedrockError(
          'Request signature verification failed.',
          'HttpSignature.VerifyFailure'));
      }
      callback();
    }],
    validateHost: ['verify', function(callback) {
      if(req.headers.host !== bedrock.config.server.host) {
        return callback(new BedrockError(
          'Host header contains an invalid host name.',
          'HttpSignature.InvalidHostHeader', {
            'public': true,
            httpStatusCode: 400,
            headers: {
              host: req.headers.host
            }
          }));
      }
      callback();
    }],
    validateNonce: ['validateHost', function(callback, results) {
      // FIXME: !!!!!!! Implement nonce tracking here !!!!!!!!!!!
      callback();
    }],
    // TODO: eventually remove and set identity elsewhere only when needed
    //       via bedrock.events.on('bedrock-passport.authenticate', ...)
    getIdentity: ['validateNonce', function(callback, results) {
      // get identity without permission check
      brIdentity.get(null, results.getPublicKey.owner, function(err, identity) {
        if(err) {
          if(err.name === 'NotFound') {
            // fallback to basic id
            return callback(null, {
              '@context': bedrock.config.constants.IDENTITY_CONTEXT_V1_URL,
              id: results.getPublicKey.owner
            });
          }
          return callback(err);
        }
        callback(null, identity);
      });
    }]
  }, function(err, results) {
    if(err) {
      return self.error(err);
    }
    req.user = {
      identity: results.getIdentity
    };
    self.success(req.user);
  });
};

// returns true if the given timestamp is before the current time
function _timestampBeforeNow(timestamp) {
  var now = new Date();
  var tsDate = new Date(timestamp);
  return tsDate < now;
}

// decides which scheme to use to look up the public key
function getPublicKey(publicKey, callback) {
  // get scheme from public key ID (URL)
  var scheme = URL.parse(publicKey).protocol || ':';
  scheme = scheme.substr(0, scheme.length - 1);

  // dereference URL if supported
  var dereferenceUrlScheme =
    bedrock.config.passport.strategies.signature.dereferenceUrlScheme;
  if(dereferenceUrlScheme[scheme]) {
    if(scheme === 'did') {
      return getDidPublicKey(publicKey, callback);
    }
    if(scheme === 'https') {
      return getHttpsPublicKey(publicKey, callback);
    }
  }

  return callback(new BedrockError(
    'URL scheme "' + scheme + '" is not supported.',
    'HttpSignature.UnsupportedUrlScheme', {
      'public': true,
      httpStatusCode: 400,
      scheme: scheme
    }));
}

function getDidPublicKey(publicKey, callback) {
  didio.get(publicKey, {
    baseUrl: bedrock.config.passport.strategies.did.didio.baseUrl
  }, callback);
}

// 1. resolve key ID => should contain public key info including key material
// (and owner)
// 2. resolve owner ID and get identity info and list of public keys
// 3. make sure key ID is listed in list of keys -- if so, verified
function getHttpsPublicKey(publicKey, callback) {
  var jsonRequest = request.defaults({
    headers: {'Accept': 'application/ld+json; application/json'},
    json: true,
    strictSSL: bedrock.config.passport.strategies.signature.strictSSLEnabled
  });

  async.auto({
    dereferencePublicKey: function(callback) {
      jsonRequest.get(publicKey, function(err, res) {
        if(err || res.statusCode !== 200) {
          var statusCode = res ? res.statusCode : 400;
          return callback(new BedrockError(
            'Public key URL unavailable.',
            'HttpSignature.VerifyFailure', {
              'public': true,
              httpStatusCode: statusCode,
              publicKey: {id: publicKey}
            }, err));
        }
        if(!(res.body && typeof res.body === 'object')) {
          return callback(new BedrockError(
            'Public key document is invalid.',
            'HttpSignature.VerifyFailure', {
              'public': true,
              httpStatusCode: 400,
              publicKey: {id: publicKey}
            }, err));
        }
        callback(null, res.body);
      });
    },
    verifyKey: ['dereferencePublicKey', function(callback, results) {
      jsigs.checkKey(results.dereferencePublicKey, function(err) {
        if(err) {
          return callback(new BedrockError(
            'Public key verification failed.',
            'HttpSignature.VerifyFailure', {
              'public': true,
              httpStatusCode: 400,
              publicKey: {id: publicKey},
              error: err.toString()
            }, err));
        }
        callback();
      });
    }]
  }, function(err, results) {
    callback(err, results.dereferencePublicKey);
  });
}
