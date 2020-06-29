/*!
 * Copyright (c) 2012-2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const brAccount = require('bedrock-account');
const {callbackify} = require('util');
const {config, util: {BedrockError, callbackify: brCallbackify}} = bedrock;
const passport = require('passport');
const URL = require('url');
require('bedrock-express');

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
 * Authenticates an express request using the given `strategy`. The event
 * `bedrock-passport.authenticate` will be emitted with the strategy, options,
 * and user information.
 *
 * @param strategy the name of the strategy to use.
 * @param req the express request.
 * @param res the express response.
 * @param [options] the options to use.
 *
 * @return a Promise that resolves once the authentication has been attempted
 *   with an object containing `user`.
 */
api.authenticate = brCallbackify(({strategy, req, res, options = {}}) => {
  const emit = async ({user}) => {
    if(user) {
      await bedrock.events.emit(
        'bedrock-passport.authenticate', {strategy, options, user});
    }
    return {user};
  };

  // handle built-in session-based authentication
  if(strategy === 'session') {
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
        // code below with
        // `app.use(api.createMiddleware({strategy: 'session'}))`
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
          return emit({user: req.user || false});
        }
        return new Promise((resolve, reject) => {
          const next = err => {
            if(err) {
              return reject(err);
            }
            resolve({user: false});
          };
          passport.authenticate('session', options, (err, user) => {
            if(user) {
              return resolve(emit({user}));
            }
            next(err);
          })(req, res, next);
        });
      }
    }
    return {user: false};
  }

  // handle non-built-in strategies
  return new Promise((resolve, reject) => {
    const next = err => {
      if(err) {
        return reject(err);
      }
      resolve({user: false});
    };
    passport.authenticate(strategy, options, (err, user) => {
      if(user) {
        return resolve(emit({user}));
      }
      next(err);
    })(req, res, next);
  });
});

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
 *
 * @return a Promise that resolves once all registered strategies have been
 *         checked with an object that looks like:
 *         results: {name: {user: [false || user]}}, user: [false || user]}
 */
api.authenticateAll = brCallbackify(async ({req, res, options = {}}) => {
  // try all strategies in parallel
  let authResults;
  const names = Object.keys(strategies);
  const strategyConfigs = config.passport.strategies;
  try {
    authResults = await Promise.all(names.map(name => {
      const strategy = strategies[name];
      const config = strategyConfigs[name] || {};
      // skip check if not auto or 'disabled' flag is set for the strategy
      if(!strategy.auto || config.disabled) {
        return false;
      }
      // overlay passed options over built-in options
      const strategyOptions = Object.assign(
        {}, strategy.options || {},
        (options.strategyOptions || {})[name] || {});
      if(name === 'session') {
        // special hidden option to reuse built-in session check
        strategyOptions.reuse = true;
      }
      return api.authenticate({
        strategy: name,
        req,
        res,
        options: strategyOptions
      });
    }));
  } catch(e) {
    // 400 if there is an error because it is presumed to be client's fault
    if(!(e instanceof BedrockError) && e.name && e.message) {
      e = new BedrockError(e.message, e.name, {public: true});
    }
    throw new BedrockError(
      'Request authentication error.', 'NotAllowedError',
      {public: true, httpStatusCode: 400}, e);
  }

  let user = false;
  const results = {};
  authResults.forEach((result, index) => {
    const name = names[index];
    results[name] = result;
    if(!user && result.user) {
      // set request user
      user = Object.assign({}, result.user);
      return;
    }

    // TODO: may want to allow users to authenticate as multiple accounts when
    //   a user wants to switch the account that is managing their identity;
    //   we support a mechanism that is simpler to implement (but perhaps more
    //   frustrating for the user) that requires them to drop management using
    //   the current account first then log into the new account and
    //   authenticate as the identity to set the new managing account

    // multiple `users` have authenticated -- check to see if more than a
    // single `account` has been used, which is not allowed
    if(user && user.account && result.user && result.user.account) {
      throw new BedrockError(
        'Authenticating as multiple accounts at once is not allowed.',
        'NotAllowedError',
        {public: true, httpStatusCode: 400});
    }

    if(result.user) {
      // combine actor capabilities
      if(result.user.actor) {
        const {actor = null} = user;
        if(!actor) {
          user.actor = Object.assign({}, result.user.account);
        } else {
          user.actor = Object.assign({}, user.actor);
          const resourceRolesA = user.actor.sysResourceRole || [];
          const resourceRolesB = result.user.actor.sysResourceRole || [];
          user.actor.sysResourceRole = resourceRolesA.concat(resourceRolesB);
        }
      }

      // track all identities
      if(result.user.identity) {
        if(!user.identities) {
          user.identities = [result.user.identity];
        } else {
          user.identities.push(result.user.identity);
        }
      }
    }
  });
  if(user) {
    user.strategies = results;
    // TODO: which `identity`? it is possible to authenticate as multiple, so
    // for now, we just allow *any* to occupy this space ... we don't have
    // a way of selecting a `default` one or anything of that sort
    if(user.identity) {
      if(!user.identities) {
        // ensure `identities` is present for simplicity
        user.identities = [user.identity];
      }
    }
    if(!user.actor) {
      // no capabilities granted
      user.actor = {sysResourceRole: []};
    }
  }
  return {results, user};
});

/**
 * Returns express middleware that will authenticate a request using the given
 * `strategy`. The event `bedrock-passport.authenticate` will be emitted
 * with the strategy, options, and user information.
 *
 * @param strategy the name of the strategy to use.
 * @param [options] the options to use.
 *
 * @return the middleware express route that is expecting a request, response,
 *           and next middleware function.
 */
api.createMiddleware = ({strategy, options = {}}) => async (req, res, next) => {
  try {
    const {user} = await api.authenticate({strategy, req, res, options});
    // if authentication found, set req.user
    if(user) {
      req.user = user;
    }
  } catch(e) {
    return next(e);
  }
  next();
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
api.optionallyAuthenticated = async (req, res, next) => {
  try {
    const {user} = await api.authenticateAll({req, res});
    // if authentication found, set req.user
    if(user) {
      req.user = user;
    }
  } catch(e) {
    return next(e);
  }
  next();
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
      'Not authenticated.', 'NotAllowedError',
      {public: true, httpStatusCode: 400}));
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
  return async (req, res, next) => {
    try {
      const {user} = await api.authenticateAll({req, res, options});
      // if authentication found, set req.user
      if(user) {
        req.user = user;
      }
    } catch(e) {
      return next(e);
    }
    if(req.user || options.optional) {
      return next();
    }
    // not authenticated
    next(new BedrockError(
      'Not authenticated.', 'NotAllowedError',
      {public: true, httpStatusCode: 400}));
  };
};

bedrock.events.on('bedrock-express.configure.router', function configure(app) {
  // define passport user serialization
  passport.serializeUser(callbackify(_serializeUser));
  passport.deserializeUser(callbackify(_deserializeUser));

  // init and attach passport
  app.use(passport.initialize(config.passport.initialize));

  // FIXME: consider not running this automatically (breaking change)

  // special-register built-in session authentication to always run
  app.use(api.createMiddleware({strategy: 'session'}));
  api.use({
    strategy: {name: 'session'},
    auto: true
  });
});

async function _serializeUser(user) {
  /* NOTE: Here we take `user` from an authentication method and specify
  the object that will be persisted in the session database. The `identity`
  and `account` properties in `user` are given special treatment. If
  `account` has an `id` property that can be retrieved via `bedrock-account`,
  then we only store the `id` in the session database and rely on persistent
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
    if(config.passport.identity.allowNonPersistent) {
      // save entire user
      Object.assign(dataToSave, user);
    } else {
      throw new BedrockError('Identity not found.', 'NotFoundError', {
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
      throw new BedrockError('Account not found.', 'NotFoundError', {
        id: user.account.id,
        httpStatusCode: 404,
        public: true
      });
    }

    // only persist account ID, rest of account persisted by
    // `bedrock-account`
    dataToSave.account = user.account.id;
  }

  return dataToSave;
}

async function _deserializeUser(data) {
  /* NOTE: Here we specify how to populate the `req.user` property
  used by express routes with information from the session. The `data`
  object was populated with whatever information was previously stored in
  the session database for the current session ID. This data needs to be
  translated into a `user` to be set to `req.user`.

  If the `identity` property is not a string in the data, we simply return the
  data in the session database as-is. The assumption is that this is from
  a non-persistent identity.

  If so, we replace the `data.identity` with that value and then return
  `data`. If not, we return `data` as-is.

  If `account` is present, it is assumed to be a string retrieved via
  `bedrock-account`.

  If `actor` is present, it is assumed to include computed capabilities
  that could not be populated via the database and is returned as-is. Otherwise,
  it is created via `bedrock-account`, if `account` is present.
  */

  const user = {};

  if(typeof data.identity !== 'string') {
    // use all data
    Object.assign(user, data);
  }

  if(typeof data.account === 'string') {
    // use latest capabilities for account to look up account to allow
    // for asynchronous changes
    const actor = await brAccount.getCapabilities({id: data.account});
    try {
      const record = await brAccount.get({actor, id: data.account});
      user.account = record.account;
    } catch(e) {
      // make error private
      throw new BedrockError(
        e.message, e.name, {public: false, id: data.account}, e);
    }

    // update actor with new capabilities
    user.actor = actor;
  }

  return user;
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
