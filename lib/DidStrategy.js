/*!
 * Copyright (c) 2015-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
let cio = require('credentials-io');
let cioVerify;
const didio = require('did-io');
const passport = require('passport');
const util = require('util');
const {promisify} = util;
const {BedrockError} = bedrock.util;
const URL = require('url');

module.exports = Strategy;

/**
 * Creates a new DidStrategy for use with passport.
 */
function Strategy() {
  passport.Strategy.call(this);
  this.name = 'did';

  // setup jsonld w/custom document loader
  cio = cio();
  const jsonld = bedrock.jsonld();
  didio.use('jsonld', jsonld);
  jsonld.documentLoader = didio.createDocumentLoader({
    baseUrl: bedrock.config.passport.strategies.did.didio.baseUrl,
    wrap: (url, callback) => bedrock.jsonld.documentLoader(url, callback),
  });
  cio.use('jsonld', jsonld, {configure: false});

  // FIXME: remove once `did-io` 0.7+ and vc.js are available
  cioVerify = promisify((identity, options = {}, callback) => {
    cio.verify(identity, options, callback);
  });
}
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate a request.
 *
 * @param req the request to authenticate.
 */
Strategy.prototype.authenticate = async req => {
  const self = this;

  // TODO: use WHATWG URL parser once node 8.x is required
  // new URL(bedrock.config.server.baseUri)
  const parsed = URL.parse(bedrock.config.server.baseUri);
  const domains = ['https://' + parsed.host, parsed.host];

  // TODO: support blinded domain check once implemented elsewhere, i.e.
  //   allow given identity/profile to be signed for a salted domain where
  //   the signer does not know the domain but the salt is then included
  //   in the profile as unsigned itself -- apply salt to expected domain
  //   and hash it to check signed domain value (or similar scheme), etc.

  // check POST data for an identity with a DID and a valid signature
  // pass to credentials-io for verification of the identity and all
  // credentials
  let results;
  try {
    results = await cioVerify(req.body);
  } catch(e) {
    return self.error(e);
  }

  if(!results.verify.verified) {
    return self.error(new BedrockError(
      'Signature verification failed.',
      'SecurityError'));
  }
  if(!domains.includes(results.verify.domain)) {
    return self.error(new BedrockError(
      'Signature domain mismatch.',
      'URLMismatchError', {
        givenDomain: results.verify.domain,
        expectedDomain: domains
      }));
  }
  // TODO: need to support use case of "upgrading" from being authenticated
  //   as the owner of an `account` to ALSO being the owner of an `identity`
  //   that is not yet managed by the `account` ... only then will all the
  //   capabilities required be present to start managing an identity
  // TODO: see `httpSignatureStrategy` to add `account` and `actor`
  req.user = {
    identity: results.verify.identity,
    credentials: results.verify.credentials
  };
  self.success(req.user);
};
