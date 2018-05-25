/*!
 * Copyright (c) 2013-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
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
  let publicKey;
  try {
    const result = await brKeyGetPublicKey({publicKey: keyQuery});
    publicKey = result.publicKey;
  } catch(err) {
    if(err && err.name === 'NotFoundError') {
      // Retrieve the public key based on the ID's
      // URL scheme when we can't find it in our database.
      return api.strategy.ldGetKey.call(api.strategy, keyQuery);
    }
    throw err;
  }
  return publicKey;
}

const brIdentityGet = promisify(brIdentity.get);
async function _getUser({keyDoc}) {
  const {owner} = keyDoc;
  let identity;
  try {
    identity = await brIdentityGet(null, owner);
  } catch(err) {
    if(err.name === 'NotFound') {
      // fallback to basic id
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
  return {id: identity.id, identity};
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
