/*!
 * Copyright (c) 2013-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const brAccount = require('bedrock-account');
const brIdentity = require('bedrock-identity');
const brKey = require('bedrock-key');
const Middleware = require('http-signature-middleware');
let jsigs = require('jsonld-signatures');
const {promisify} = require('util');
const BedrockError = bedrock.util.BedrockError;
let didio = require('did-io');
let jsonld = require('jsonld');

const api = {};
module.exports = api;

api.strategy = new Middleware({name: 'signature'});
api.strategy.use('getKey', _getKey);
api.strategy.use('getUser', _getUser);
api.strategy.use('validateRequest', _validateRequest);

bedrock.events.on('bedrock.init', () => {
  // get configured lib instances
  jsonld = jsonld();
  didio = didio();
  didio.use('jsonld', jsonld);
  jsonld.documentLoader = didio.createDocumentLoader({
    baseUrl: bedrock.config.passport.strategies.did.didio.baseUrl,
    wrap: (url, callback) => bedrock.jsonld.documentLoader(url, callback),
  });
  jsigs = jsigs();
  jsigs.use('jsonld', jsonld);
  api.strategy.use('jsigs', jsigs);
});

const brKeyGetPublicKey = promisify(brKey.getPublicKey);
async function _getKey(keyQuery) {
  try {
    const {publicKey} = await brKeyGetPublicKey({publicKey: keyQuery});
    return publicKey;
  } catch(err) {
    if(err && err.name === 'NotFoundError') {
      // Retrieve the public key based on the ID's
      // URL scheme when we can't find it in our database.
      return api.strategy.ldGetKey.call(api.strategy, keyQuery);
    }
    throw err;
  }
}

const brIdentityGet = promisify(getIdentity);
async function _getUser({keyDoc}) {
  const {owner} = keyDoc;
  let identityRecord;
  try {
    identityRecord = await brIdentityGet(null, owner);
  } catch(err) {
    if(err.name === 'NotFound') {
      // fallback to basic non-persistent id
      return {
        id: owner,
        identity: {
          '@context': bedrock.config.constants.IDENTITY_CONTEXT_V1_URL,
          id: owner
        }
      };
    }
    throw err;
  }

  const {identity, meta} = identityRecord;
  const user = {identity};

  // TODO: consider aliasing `user.actor` to `user.capabilities` or `user.ocaps`

  // see if an account exists for the identity
  if(typeof meta['bedrock-account'] === 'object' &&
    typeof meta['bedrock-account'].account === 'string') {
    const id = meta['bedrock-account.account'];
    // identity is managed by `account`
    user.account = await brAccount.get({actor: null, id});
    user.actor = await brAccount.getCapabilities({id: user.account.id});
  } else {
    // no `account`, so copy identity into actor
    user.actor = Object.assign({}, identity);
  }

  return user;
}

async function _validateRequest(req) {
  const host = req.header('host');
  if(host !== bedrock.config.server.host) {
    throw new BedrockError(
      'Host header contains an invalid host name.',
      'HttpSignature.InvalidHostHeader', {
        'public': true,
        httpStatusCode: 400,
        headers: {host}
      });
  }
}

// TODO: remove once bedrock-identity API is updated to return {identity, meta}
// helper to get identity and meta at once
function getIdentity({actor, identity}, callback) {
  brIdentity.get(actor, identity, (err, identity, meta) => {
    if(err) {
      return callback(err);
    }
    callback(null, {identity, meta});
  });
}
