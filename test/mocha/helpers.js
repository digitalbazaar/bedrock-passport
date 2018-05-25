/*!
 * Copyright (c) 2015-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const async = require('async');
const brKey = require('bedrock-key');
const brIdentity = require('bedrock-identity');
const config = require('bedrock').config;
const database = require('bedrock-mongodb');
const httpSignatureHeader = require('http-signature-header');
const httpSignatureCrypto = require('http-signature-crypto');
const jsprim = require('jsprim');

const api = {};
module.exports = api;

// mutates requestOptions
api.createHttpSignatureRequest = async (
  {algorithm, identity, requestOptions}) => {
  if(!requestOptions.headers.date) {
    requestOptions.headers.date = jsprim.rfc1123(new Date());
  }
  const includeHeaders = ['date', 'host', '(request-target)'];
  const plaintext = httpSignatureHeader.createSignatureString(
    {includeHeaders, requestOptions});
  const keyId = identity.keys.publicKey.id;
  const authzHeaderOptions = {includeHeaders, keyId};
  const cryptoOptions = {plaintext};
  if(algorithm.startsWith('rsa')) {
    authzHeaderOptions.algorithm = algorithm;
    const alg = algorithm.split('-');
    const {privateKeyPem} = identity.keys.privateKey;
    cryptoOptions.algorithm = alg[0];
    cryptoOptions.privateKeyPem = privateKeyPem;
    cryptoOptions.hashType = alg[1];
  }
  if(algorithm === 'ed25519') {
    const {privateKeyBase58} = identity.keys.privateKey;
    cryptoOptions.algorithm = algorithm;
    cryptoOptions.privateKeyBase58 = privateKeyBase58;
  }

  authzHeaderOptions.signature = await httpSignatureCrypto.sign(cryptoOptions);
  requestOptions.headers.Authorization = httpSignatureHeader.createAuthzHeader(
    authzHeaderOptions);
};

api.createIdentity = userName => {
  const newIdentity = {
    id: 'https://' + config.server.host + '/tests/i/' + userName,
    type: 'Identity',
    sysSlug: userName,
    label: userName,
    email: userName + '@bedrock.dev',
    sysPassword: 'password',
    sysPublic: ['label', 'url', 'description'],
    sysResourceRole: [],
    url: config.server.baseUri,
    description: userName,
    sysStatus: 'active'
  };
  return newIdentity;
};

api.createKeyPair = options => {
  const {publicKey, privateKey, publicKeyBase58, privateKeyBase58, userName} =
    options;
  let ownerId = null;
  const keyId = options.keyId;
  if(userName === 'userUnknown') {
    ownerId = '';
  } else {
    ownerId = options.userId;
  }
  const newKeyPair = {
    publicKey: {
      '@context': 'https://w3id.org/identity/v1',
      id: 'https://' + config.server.host + '/keys/' + keyId,
      owner: ownerId,
      label: 'Signing Key 1',
    },
    privateKey: {
      owner: ownerId,
      label: 'Signing Key 1',
      publicKey: 'https://' + config.server.host + '/keys/' + keyId,
    }
  };
  if(publicKey && privateKey) {
    newKeyPair.publicKey.type = 'RsaVerificationKey2018';
    newKeyPair.publicKey.publicKeyPem = publicKey;
    newKeyPair.privateKey.privateKeyPem = privateKey;
  }
  if(publicKeyBase58 && privateKeyBase58) {
    newKeyPair.publicKey.type = 'Ed25519VerificationKey2018';
    newKeyPair.publicKey.publicKeyBase58 = publicKeyBase58;
    newKeyPair.privateKey.privateKeyBase58 = privateKeyBase58;
  }
  return newKeyPair;
};

api.prepareDatabase = (mockData, callback) => async.series([
  callback => api.removeCollections(callback),
  callback => insertTestData(mockData, callback)
], callback);

api.randomDate = (start, end) => {
  return new Date(
    start.getTime() + Math.random() * (end.getTime() - start.getTime()));
};

api.removeCollections = callback => {
  const collectionNames =
    ['credentialProvider', 'identity', 'publicKey', 'eventLog'];
  database.openCollections(collectionNames, err => {
    if(err) {
      return callback(err);
    }
    async.each(collectionNames, (collectionName, callback) =>
      database.collections[collectionName].remove({}, callback),
    err => callback(err));
  });
};

api.removeCollection = (collection, callback) => {
  const collectionNames = [collection];
  database.openCollections(collectionNames, err => {
    if(err) {
      return callback(err);
    }
    async.each(collectionNames, (collectionName, callback) =>
      database.collections[collectionName].remove({}, callback),
    err => callback(err));
  });
};

// Insert identities and public keys used for testing into database
function insertTestData(mockData, callback) {
  async.forEachOf(mockData.identities, (identity, key, callback) =>
    async.parallel([
      callback => brIdentity.insert(null, identity.identity, callback),
      callback => brKey.addPublicKey(
        {actor: null, publicKey: identity.keys.publicKey}, callback)
    ], callback),
  err => {
    if(err) {
      if(err.name === 'DuplicateError') {
        // duplicate error means test data is already loaded
        return callback(err);
      }
    }
    callback();
  }, callback);
}
