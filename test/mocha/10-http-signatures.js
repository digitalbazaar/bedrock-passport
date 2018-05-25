/*!
 * Copyright (c) 2016-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const axios = require('axios');
const bedrock = require('bedrock');
const config = bedrock.config;
const helpers = require('./helpers');
const mockData = require('./mock.data');
const url = require('url');
const {util} = bedrock;

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const urlObj = {
  protocol: 'https',
  host: config.server.host,
  pathname: '/tests/bedrock-passport/http-signature-test'
};

describe('bedrock-passport', () => {
  describe('authenticated requests using http-signature', () => {
    describe('using dereference lookup', () => {
      it('request succeeds with ed25519 key', async () => {
        const identity = mockData.identities.zeta;
        const clonedUrlObj = util.clone(urlObj);
        const requestOptions = {
          headers: {},
          method: 'get',
          url: url.format(clonedUrlObj),
        };
        await helpers.createHttpSignatureRequest(
          {algorithm: 'ed25519', identity, requestOptions});
        let res;
        try {
          res = await axios(requestOptions);
        } catch(err) {
          should.not.exist(err);
        }
        res.status.should.equal(200);
        // test endpoint returns an identity document
        should.exist(res.data.identity.id);
        res.data.identity.id.should.equal(identity.identity.id);
      });
      it('request succeeds with rsa key', async () => {
        const identity = mockData.identities.alpha;
        const clonedUrlObj = util.clone(urlObj);
        const requestOptions = {
          headers: {},
          method: 'get',
          url: url.format(clonedUrlObj),
        };
        await helpers.createHttpSignatureRequest(
          {algorithm: 'rsa-sha256', identity, requestOptions});
        const res = await axios(requestOptions);
        res.status.should.equal(200);
        // test endpoint returns an identity document
        should.exist(res.data.identity.id);
        res.data.identity.id.should.equal(identity.identity.id);
      });

      // beta signs the request with a private key that does not match the
      // published public key
      it('dereference lookup fails', async () => {
        const identity = mockData.identities.beta;
        const clonedUrlObj = util.clone(urlObj);
        const requestOptions = {
          headers: {},
          method: 'get',
          url: url.format(clonedUrlObj),
        };
        await helpers.createHttpSignatureRequest(
          {algorithm: 'rsa-sha256', identity, requestOptions});
        let res;
        try {
          res = await axios(requestOptions);
        } catch(err) {
          err.response.status.should.equal(400);
          should.exist(err.response.data);
          err.response.data.should.be.an('object');
          const {data} = err.response;
          should.exist(data.type);
          data.type.should.equal('PermissionDenied');
        }
        should.not.exist(res);
      });

      // gamma has no published public key document
      it('should fail if key document URL is unavailable', async () => {
        const identity = mockData.identities.gamma;
        const clonedUrlObj = util.clone(urlObj);
        const requestOptions = {
          headers: {},
          method: 'get',
          url: url.format(clonedUrlObj),
        };
        await helpers.createHttpSignatureRequest(
          {algorithm: 'rsa-sha256', identity, requestOptions});
        let res;
        try {
          res = await axios(requestOptions);
        } catch(err) {
          err.response.status.should.equal(400);
          should.exist(err.response.data);
          err.response.data.should.be.an('object');
          const {data} = err.response;
          should.exist(data.type);
          data.type.should.equal('PermissionDenied');
          should.exist(data.cause);
          should.exist(data.cause.type);
          data.cause.type.should.equal('NotFoundError');
          should.exist(data.cause.message);
          data.cause.message.should.equal('Public key URL unavailable.');
        }
        should.not.exist(res);
      });
      // delta has no published owner document
      it('should fail if owner URL is unavailable', async () => {
        const identity = mockData.identities.delta;
        const clonedUrlObj = util.clone(urlObj);
        const requestOptions = {
          headers: {},
          method: 'get',
          url: url.format(clonedUrlObj),
        };
        await helpers.createHttpSignatureRequest(
          {algorithm: 'rsa-sha256', identity, requestOptions});
        let res;
        try {
          res = await axios(requestOptions);
        } catch(err) {
          err.response.status.should.equal(400);
          should.exist(err.response.data);
          err.response.data.should.be.an('object');
          const {data} = err.response;
          should.exist(data.type);
          data.type.should.equal('PermissionDenied');
          should.exist(data.cause);
          should.exist(data.cause.type);
          data.cause.type.should.equal('DataError');
          should.exist(data.cause.message);
          data.cause.message.should.equal(
            'Public key verification failed: Error: The public key is not ' +
            'owned by its declared owner.');
        }
        should.not.exist(res);
      });

      // epsilon owner doc references alpha owner public key doc
      it('fails if owner doc references wrong public key', async () => {
        const identity = mockData.identities.epsilon;
        const clonedUrlObj = util.clone(urlObj);
        const requestOptions = {
          headers: {},
          method: 'get',
          url: url.format(clonedUrlObj),
        };
        await helpers.createHttpSignatureRequest(
          {algorithm: 'rsa-sha256', identity, requestOptions});
        let res;
        try {
          res = await axios(requestOptions);
        } catch(err) {
          err.response.status.should.equal(400);
          should.exist(err.response.data);
          err.response.data.should.be.an('object');
          const {data} = err.response;
          should.exist(data.type);
          data.type.should.equal('PermissionDenied');
          should.exist(data.cause);
          should.exist(data.cause.type);
          data.cause.type.should.equal('DataError');
          should.exist(data.cause.message);
          data.cause.message.should.equal(
            'Public key verification failed: Error: The public key is not ' +
            'owned by its declared owner.');
        }
        should.not.exist(res);
      });
      // TODO:
      it('Fails if public key document is invalid.');
    });
  });
});
