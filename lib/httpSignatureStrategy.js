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
const {BedrockError} = bedrock.util;
let didio = require('did-io');
let jsonld = require('jsonld');

const api = {};
module.exports = api;

api.strategy = new Middleware();
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

async function _getKey(keyQuery) {
  try {
    const {publicKey} = await brKey.getPublicKey({publicKey: keyQuery});
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

async function _getUser({keyDoc}) {
  const {owner} = keyDoc;
  let identityRecord;
  try {
    identityRecord = await brIdentity.get({actor: null, id: owner});
  } catch(err) {
    if(err.name === 'NotFoundError') {
      // fallback to basic non-persistent id
      return {
        id: owner,
        identity: {
          // TODO: determine if this context is necessary or implied
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
  // for future transition away from "actor" concept

  // see if an account exists for the identity
  if(typeof meta['bedrock-account'] === 'object' &&
    typeof meta['bedrock-account'].account === 'string') {
    const id = meta['bedrock-account.account'];
    // identity is managed by `account`
    [user.account, user.actor] = await Promise.all([
      brAccount.get({actor: null, id}),
      brAccount.getCapabilities({id: user.account.id})]);
  } else {
    // no `account`, so copy identity into actor
    user.actor = {
      // TODO: deprecate `id` on actor
      id: identity.id,
      sysResourceRole: [].concat(identity.sysResourceRole || [])
    };
  }

  return user;
}

async function _validateRequest(req) {
  const host = req.header('host');
  if(host !== bedrock.config.server.host) {
    throw new BedrockError(
      'Host header contains an invalid host name.',
      'SyntaxError', {
        public: true,
        httpStatusCode: 400,
        headers: {host}
      });
  }
}
