/*!
 * Copyright (c) 2012-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const _ = require('lodash');
const async = require('async');
const bedrock = require('bedrock');
const brAccount = require('bedrock-account');
const brIdentityApi = require('bedrock-identity');
const {callbackify, promisify} = require('util');
const config = bedrock.config;
const passport = require('passport');
const BedrockError = bedrock.util.BedrockError;
const DidStrategy = require('./DidStrategy');
const httpSignatureStrategy = require('./httpSignatureStrategy');
const URL = require('url');
require('bedrock-express');
require('bedrock-did-client');

const brIdentity = {
  exists: promisify(brIdentityApi.exists),
  get: promisify(brIdentityApi.get)
};

// load config defaults
require('./config');

// module API
const api = {};
module.exports = api;

// expose passport
api.passport = passport;

// registered strategies
const strategies = {};

// permitted CORS methods w/session authentication
const permittedCorsMethods = ['GET', 'HEAD', 'OPTIONS'];

/**
 * Registers a new passport strategy.
 *
 * @param options the options to use:
 *          strategy the strategy to use.
 *          [auto] true to automatically run authenticate.
 *          [options] the options to pass if auto-running authenticate.
 */
api.use = options => {
  if(!options || !options.strategy || !('name' in options.strategy)) {
    throw new Error('options.strategy must be a passport Strategy.');
  }
  const name = options.strategy.name;
  if(name in strategies) {
    throw new Error('"' + options.strategy.name + '" already registered.');
  }
  strategies[name] = options;
  // `session` strategy is built into passport by default
  if(name !== 'session') {
    passport.use(options.strategy);
  }
};

/**
 * Returns express middleware that will authenticate a request using the given
 * `strategy`. The event `bedrock-passport.authenticate` will be emitted
 * with the strategy, options, and user information.
 *
 * @param strategy the name of the strategy to use.
 * @param [options] the options to use.
 * @param callback(err, user, info) the callback to call once authentication
 *          has been attempted.
 *
 * @return the middleware express route that is expecting a request, response,
 *           and next middleware function.
 */
api.authenticate = (strategy, options, callback) => {
  if(typeof options === 'function') {
    callback = options;
    options = {};
  }
  options = options || {};
  // handle built-in session-based authentication
  if(strategy === 'session') {
    return (req, res, next) => {
      // ensure authN event after successful authN
      const done = emitter(callback || function(err) {
        next(err);
      });
      // restrict session-based authentication to when:
      // 1. There is no origin header set.
      // 2. The origin header matches the host header.
      // 3. The request method is in a list of default permitted CORS methods.
      // TODO: add an option to allow controlling permittedCorsMethods for
      // particular handlers that know what they're doing
      const origin = ('origin' in req.headers ?
        URL.parse(req.headers.origin).host : null);
      if(origin === null || req.headers.host === origin ||
        permittedCorsMethods.indexOf(req.method) !== -1 ||
        _checkAllowedHosts(origin, options.allowHosts)) {
        if(options.allowUrlEncoded || !(
          req.is('urlencoded') || req.is('multipart'))) {
          // reuse existing check (express auto-runs a session check per
          // code below with `app.use(api.authenticate('session'))`
          // TODO: potentially refactor to avoid this auto-check in the future,
          // but it would be a breaking change
          // FIXME: `req.isAuthenticated` is not technically granular enough
          // to determine if `session` strategy was responsible for previous
          // authentication, but presently works because session is always
          // checked and if another method was concurrently checked, both would
          // fail if the user didn't match; however, should the automatic
          // session check be removed, then the degenerate case where a user
          // was authenticated via another method and then checked against
          // session this will pass when it should potentially fail
          if(options.reuse && req.isAuthenticated()) {
            return done(null, req.user);
          }
          return passport.authenticate('session', options)(
            req, res, err => done(err, req.user || false));
        }
      }
      return done(null, false);
    };
  }

  if(typeof callback !== 'function') {
    throw new TypeError('callback must be a function.');
  }

  // handle non-built-in strategies
  return passport.authenticate(strategy, options, emitter(callback));

  function emitter(callback) {
    return (err, user, info) => {
      if(!err && user) {
        return bedrock.events.emit('bedrock-passport.authenticate', {
          strategy: strategy,
          options: options,
          user: user,
          info: info
        }, err => callback(err, user, info));
      }
      callback(err, user, info);
    };
  }
};

/**
 * Checks authentication of a request using all registered strategies. The
 * results of each strategy will be included in the output.
 *
 * If more than one strategy was attempted, then the identity associated with
 * every attempted strategy must match, or an error will be raised.
 *
 * @param req the request.
 * @param res the response.
 * @param [options] options to use:
 *          [strategyOptions] an object of strategy-specific options, keyed by
 *            strategy name.
 * @param callback(err, result) called with error or null and the
 *          found auth info as {strategies: {}, user: identity} or false.
 */
api.checkAuthentication = (req, res, options, callback) => {
  if(typeof options === 'function') {
    callback = options;
    options = {};
  }

  const result = {};

  // try all strategies in parallel
  const parallel = Object.keys(strategies).map(name => {
    const strategy = strategies[name];
    const config = bedrock.config.passport.strategies[name] || {};
    return callback => {
      // skip check if not auto or 'disabled' flag is set for the strategy
      if(!strategy.auto || config.disabled) {
        return callback(null, false);
      }
      // overlay passed options over built-in options
      const strategyOptions = _.assign(
        {}, strategy.options || {},
        (options.strategyOptions || {})[name] || {});
      if(name === 'session') {
        // special hidden option to reuse built-in session check
        strategyOptions.reuse = true;
      }
      api.authenticate(name, strategyOptions, (err, user) => {
        result[name] = err ? false : user;
        callback(err, user);
      })(req, res, err => callback(err));
    };
  });

  async.auto({
    auth: callback => async.parallel(parallel, callback),
    compare: ['auth', (results, callback) => {
      // do not permit more than one attempted strategy
      let user_ = false;
      for(const name in result) {
        const user = result[name];
        if(!user) {
          continue;
        }
        if(user_) {
          return callback(new BedrockError(
            'Multiple simultaneous authentication methods are disallowed.',
            'NotAllowedError',
            {'public': true, httpStatusCode: 400}));
        }
        user_ = user;
      }
      callback(null, user_);
    }]
  }, (err, results) => {
    // 400 if there is an error
    if(err) {
      if(!(err instanceof BedrockError) && err.name && err.message) {
        err = new BedrockError(err.message, err.name, {public: true});
      }
      return callback(new BedrockError(
        'Request authentication error.', 'PermissionDenied',
        {'public': true, httpStatusCode: 400}, err));
    }
    callback(null, {strategies: result, user: results.compare});
  });
};

/**
 * Process a request that has been optionally authenticated. Code using this
 * call can check if the request is authenticated by testing if req.user and
 * req.user.identity are set.
 *
 * @param req the request.
 * @param res the response.
 * @param next the next route handler.
 */
api.optionallyAuthenticated = (req, res, next) => {
  api.checkAuthentication(req, res, (err, info) => {
    if(err) {
      return next(err);
    }
    // if authorization found, set req.user
    if(info) {
      req.user = info.user;
    }
    next();
  });
};

/**
 * Ensure a request has been authenticated. Redirect if not and it looks like
 * a browser GET request, otherwise set 400 error.
 *
 * @param req the request.
 * @param res the response.
 * @param next the next route handler.
 */
api.ensureAuthenticated = (req, res, next) => {
  api.optionallyAuthenticated(req, res, err => {
    if(err) {
      return next(err);
    }
    // authenticated
    if(req.user) {
      return next();
    }
    // not authenticated
    next(new BedrockError(
      'Not authenticated.', 'PermissionDenied',
      {'public': true, httpStatusCode: 400}));
  });
};

/**
 * Create an authenticator to ensure a request has been authenticated.
 *
 * @param [options] the options to use.
 *          [optional] true to only optionally authenticate.
 *          [strategy] **NOT IMPLEMENTED** one or more strategy names to use
 *            instead of the default automatic strategies.
 *          [strategyOptions] an object of strategy-specific options, keyed by
 *            strategy name.
 *            [session] session strategy-options:
 *              [allowUrlEncoded] true to permit session-based authentication
 *                on requests that contain URL-encoded content; this is off by
 *                default to prevent CSRFs and if this is enabled it must be
 *                combined with CSRF protections (eg: CSRF tokens).
 *              [allowHosts] a list of cross-domain hosts to allow, '*' for
 *                any.
 */
api.createAuthenticator = options => {
  options = options || {};
  return (req, res, next) => {
    api.checkAuthentication(req, res, options, (err, info) => {
      if(err) {
        return next(err);
      }
      // if authorization found, set req.user
      if(info) {
        req.user = info.user;
      }
      if(req.user || options.optional) {
        return next();
      }
      // not authenticated
      next(new BedrockError(
        'Not authenticated.', 'PermissionDenied',
        {'public': true, httpStatusCode: 400}));
    });
  };
};

bedrock.events.on('bedrock-express.configure.router', function configure(app) {
  // define passport user serialization
  passport.serializeUser(callbackify(_serializeUser));
  passport.deserializeUser(callbackify(_deserializeUser));

  // init and attach passport
  app.use(passport.initialize(bedrock.config.passport.initialize));

  // special-register built-in session authentication to always run
  app.use(api.authenticate('session'));
  api.use({
    strategy: {name: 'session'},
    auto: true
  });

  // register default authentication strategies
  api.use({
    strategy: httpSignatureStrategy.strategy,
    auto: true
  });
  api.use({
    strategy: new DidStrategy(),
    auto: false
  });
});

async function _serializeUser(user) {
  /* NOTE: Here we take `user` from an authentication method and specify
  the object that will be persisted in the session database. The `identity`
  and `account` properties in `user` are given special treatment. If
  `account` has an `id` property that can be retrieved via `bedrock-account`,
  then we only store the `id` in the session database and rely on presistent
  storage of the account for later retrieval. The same rule is applied to
  `identity` using the `bedrock-identity` module.

  If an `identity` is set but there is no such identity in `bedrock-identity`
  then we assume we have a non-persistent identity and we cache everything
  about that identity in the session database if permitted by the
  `passport.identity.allowNonPersistent` configuration flag. Once the session
  is gone, that information will also be gone.

  If an `account` is set but there is no such account in `bedrock-account`,
  an error is thrown. Non-persistent accounts are not presently supported.
  */

  const dataToSave = {};

  if(user.identity) {
    const exists = await brIdentity.exists(null, user.identity.id);
    if(exists) {
      // only persist identity ID, rest of identity persisted by
      // `bedrock-identity`
      dataToSave.identity = user.identity.id;
    } else if(config.passport.identity.allowNonPersistent) {
      // save entire user
      _.assign(dataToSave, user);
    } else {
      throw new BedrockError('Identity not found.', 'NotFound', {
        id: user.identity.id,
        httpStatusCode: 404,
        public: true
      });
    }
  }

  if(user.account) {
    const exists = await brAccount.exists(
      {actor: null, id: user.account.id});
    if(!exists) {
      throw new BedrockError('Account not found.', 'NotFound', {
        id: user.identity.id,
        httpStatusCode: 404,
        public: true
      });
    }

    // only persist account ID, rest of account persisted by
    // `bedrock-account`
    dataToSave.account = user.account.id;
  }
}

async function _deserializeUser(data) {
  /* NOTE: Here we specify how to populate the `req.user` property
  used by express routes with information from the session. The `data`
  object was populated with whatever information was previously stored in
  the session database for the current session ID. This data needs to be
  translated into a `user` to be set to `req.user`.

  If the `identity` property is not a string in the data, we simply return the
  data in the session database as-is. The assumption is that this is from
  a non-persistent identity. Otherwise, we look to see if the `identity` is an
  ID that refers to a persistent user that can be retrieved via
  `bedrock-identity`.

  If so, we replace the `data.identity` with that value and then return
  `data`. If not, we return `data` as-is.

  If `account` is present, it is assumed to be a string retrieved via
  `bedrock-account`.

  If `actor` is present, it is assumed to include computed capabilities
  that could not be populated via the database and is returned as-is. Otherwise,
  it is created via `bedrock-account`, if `account` is present, and
  `bedrock-identity` if it is not.
  */

  const user = {};

  if(typeof data.identity !== 'string') {
    // use all data
    _.assign(user, data);
  } else {
    // look up persistent identity
    const actor = {id: data.identity};
    try {
      user.identity = await brIdentity.get(actor, data.identity);
    } catch(e) {
      // make error private
      throw new BedrockError(
        e.message, e.name, {public: false, id: data.identity}, e);
    }
  }

  if(typeof data.account === 'string') {
    // use latest capabilities for account to look up account to allow
    // for asynchronous changes
    const actor = await brAccount.getCapabilities({id: data.account});
    try {
      user.account = await brAccount.get({actor, id: data.account});
    } catch(e) {
      // make error private
      throw new BedrockError(
        e.message, e.name, {public: false, id: data.account}, e);
    }

    // update actor with new capabilities
    user.actor = actor;
  }
}

function _checkAllowedHosts(host, allowed) {
  if(!allowed) {
    return false;
  }
  if(!Array.isArray(allowed)) {
    allowed = [allowed];
  }
  return (allowed.indexOf('*') !== -1 || allowed.indexOf(host) !== -1);
}
