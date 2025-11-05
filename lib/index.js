/*!
 * Copyright (c) 2012-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as brAccount from '@bedrock/account';
import {callbackify} from 'node:util';
import passport from 'passport';
import '@bedrock/express';

// load config defaults
import './config.js';

const {config, util: {BedrockError}} = bedrock;

// expose passport
export {passport};

// registered strategies
const strategies = {};

// cross-origin methods for requests (with no request body) that are allowed to
// be used (with hosts in the allowed hosts list) and session-based authn
const PERMITTED_ALLOWED_HOSTS_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Registers a new passport strategy.
 *
 * @param {object} options - The options to use:
 *   strategy the strategy to use.
 *   [auto] true to automatically run authenticate.
 *   [options] the options to pass if auto-running authenticate.
 */
export function use(options) {
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
}

/**
 * Authenticates an express request using the given `strategy`. The event
 * `bedrock-passport.authenticate` will be emitted with the strategy, options,
 * and user information.
 *
 * @param {object} options - The options to use.
 * @param {string} options.strategy - The name of the strategy to use.
 * @param {object} options.req - The express request.
 * @param {object} options.res - The express response.
 * @param {object} [options.options] - The authentication options to use.
 *
 * @returns {Promise<object>} A Promise that resolves once the authentication
 *   has been attempted with an object containing `user`.
 */
export async function authenticate({strategy, req, res, options = {}}) {
  const emit = async ({user}) => {
    if(user) {
      await bedrock.events.emit(
        'bedrock-passport.authenticate', {strategy, options, user});
    }
    return {user};
  };

  // handle built-in session-based authentication
  if(strategy === 'session') {
    /* Note: Session-based authentication is only permitted when the request is
    not coming from a client that follows a CORS policy (i.e., a "modern
    browser"). Such browsers act as deputies for users, sending along their
    cookies when CORS policy allows it, relying upon CORS and CSRF tokens (at
    the application layer) to provide protection against confused deputy
    attacks. None of this is relevant for any client that cannot become a
    confused deputy or that would not follow such policy anyway.

    A modern browser will NOT send a `fetch` cross-origin request
    *WITH COOKIES* unless at least these are true:

    1. The `Access-Control-Allow-Origin` is set with a specific origin value,
      i.e., using the wildcard value `*` will NOT allow any cookies to be sent.
    2. The `Access-Control-Allow-Credentials` header must be set to `true`.
    3. Any cookies to be sent must have `SameSite=None`.

    Similarly, a modern browser that uses the old XMLHttpRequest API and sets
    `withCredentials=true` will only be able to successfully send a
    cross-origin request *WITH COOKIES* if the above list holds.

    Therefore, any application that does not want particular cookies used
    across origins by `fetch` should set them to `SameSite=None` and either set
    no CORS headers or, usually it is preferable, set the CORS header value:
    `Access-Control-Allow-Origin: *`. None of these protections are considered
    here and should be externally applied as appropriate.

    However, a modern browser could still send a form GET or POST request (not
    using the `fetch` API or `XMLHttpRequest`), provided that it has no body or
    the body's media type (aka form encoding type) is one of the following:

    `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`.

    Therefore, if a request includes a body with any other media type (such as
    the commonly used `application/json`) then it indicates a non-cross-origin
    request or a cross-origin request that was initiated via the `fetch` API or
    `XMLHttpRequest` where the appropriate CORS and cookie settings should
    already be in place (or the request did not come from a modern browser).

    Taking all of this into account, here we disallow session-based
    authentication if all of these are true:

    1. The request is possibly a modern browser cross-origin request, AND
    2. The request possibly originated from an HTML form submission, AND
    3. Neither the authentication options allow URL encoded forms NOR is
      the host allow-listed for requests w/o entity bodies. */
    if(_maybeModernCrossOriginRequest(req) && _maybeFormOriginated(req) &&
      !(options.allowUrlEncoded || _isCrossOriginAllowedHost({req, options}))) {
      return {user: false};
    }

    /* Note: here we reuse an existing check to avoid checking again (express
    auto-runs a session check per code below with:

    `app.use(createMiddleware({strategy: 'session'}))`.

    However, there is presently no way to determine which strategy caused
    `req.isAuthenticated()` to return `true` (when it does). Since the
    `session` strategy is currently always automatically checked as mentioned,
    if another strategy produced a different user then authentication would
    fail (return `false`). So, while there is presently no issue on account of
    this, if the behavior ever changes, such that the `session` strategy does
    not auto-run, then it could become possible for another strategy to succeed
    and possibly authenticate a different user from what the `session` strategy
    might authenticate (or the `session` strategy might even fail). This note
    is to help maintainers ensure this is adjusted if that change occurs. */
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
}

/**
 * Checks authentication of a request using all registered strategies. The
 * results of each strategy will be included in the output.
 *
 * If more than one strategy was attempted, then the identity associated with
 * every attempted strategy must match, or an error will be raised.
 *
 * @param {object} options - The options to use.
 * @param {object} options.req - The request.
 * @param {object} options.res - The response.
 * @param {object} [options.options] - The authentication options to use:
 *   [strategyOptions] an object of strategy-specific options, keyed by
 *     strategy name.
 *
 * @returns {Promise} A Promise that resolves once all registered strategies
 *   have been checked with an object that looks like:
 *   results: {name: {user: [false || user]}}, user: [false || user]}.
 */
export async function authenticateAll({req, res, options = {}}) {
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
      const strategyOptions = {
        ...strategy.options,
        ...(options.strategyOptions || {})[name]
      };
      if(name === 'session') {
        // special hidden option to reuse built-in session check
        strategyOptions.reuse = true;
      }
      return authenticate({
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
      user = {...result.user};
      return;
    }

    // multiple `users` have authenticated -- check to see if more than a
    // single `account` has been used, which is not allowed
    if(user && user.account && result.user && result.user.account) {
      throw new BedrockError(
        'Authenticating as multiple accounts at once is not allowed.',
        'NotAllowedError',
        {public: true, httpStatusCode: 400});
    }
  });
  if(user) {
    user.strategies = results;
  }
  return {results, user};
}

/**
 * Returns express middleware that will authenticate a request using the given
 * `strategy`. The event `bedrock-passport.authenticate` will be emitted
 * with the strategy, options, and user information.
 *
 * @param {object} options - The options to use.
 * @param {string} options.strategy - The name of the strategy to use.
 * @param {object} [options.options] - The authentication options to use.
 *
 * @returns {Function} The middleware express route that is expecting a
 *   request, response, and next middleware function.
 */
export function createMiddleware({strategy, options = {}}) {
  return async (req, res, next) => {
    try {
      const {user} = await authenticate({strategy, req, res, options});
      // if authentication found, set req.user
      if(user) {
        req.user = user;
      }
    } catch(e) {
      return next(e);
    }
    next();
  };
}

/**
 * Process a request that has been optionally authenticated. Code using this
 * call can check if the request is authenticated by testing if req.user is set.
 *
 * @param {object} req - The request.
 * @param {object} res - The response.
 * @param {Function} next - The next route handler.
 *
 * @returns {Promise} Nothing or result of next() on error.
 */
export async function optionallyAuthenticated(req, res, next) {
  try {
    const {user} = await authenticateAll({req, res});
    // if authentication found, set req.user
    if(user) {
      req.user = user;
    }
  } catch(e) {
    return next(e);
  }
  next();
}

/**
 * Ensure a request has been authenticated. Redirect if not and it looks like
 * a browser GET request, otherwise set 400 error.
 *
 * @param {object} req - The request.
 * @param {object} res - The response.
 * @param {Function} next - The next route handler.
 */
export function ensureAuthenticated(req, res, next) {
  optionallyAuthenticated(req, res, err => {
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
}

/**
 * Create an authenticator to ensure a request has been authenticated.
 *
 * @param {object} [options] - The options to use:
 *   [optional] true to only optionally authenticate.
 *   [strategy] **NOT IMPLEMENTED** one or more strategy names to use
 *     instead of the default automatic strategies.
 *   [strategyOptions] an object of strategy-specific options, keyed by
 *     strategy name.
 *   [session] session strategy-options:
 *     [allowUrlEncoded] true to permit session-based authentication
 *       on requests that contain URL-encoded content; this is off by
 *       default to prevent CSRFs and if this is enabled it must be
 *       combined with CSRF protections (eg: CSRF tokens).
 *     [allowHosts] a list of cross-origin hosts to allow GET, HEAD, OPTIONS
 *       requests (with empty bodies) from, '*' for any.
 *
 * @returns {Function} The authenticator middleware.
 */
export function createAuthenticator(options = {}) {
  return async (req, res, next) => {
    try {
      const {user} = await authenticateAll({req, res, options});
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
}

bedrock.events.on('bedrock-express.configure.router', function configure(app) {
  // define passport user serialization
  passport.serializeUser(callbackify(_serializeUser));
  passport.deserializeUser(callbackify(_deserializeUser));

  // init and attach passport
  app.use(passport.initialize(config.passport.initialize));

  // FIXME: consider not running this automatically (breaking change)

  // special-register built-in session authentication to always run
  app.use(createMiddleware({strategy: 'session'}));
  use({
    strategy: {name: 'session'},
    auto: true
  });
});

async function _serializeUser(user) {
  /* NOTE: Here we take `user` from an authentication method and specify
  the object that will be persisted in the session database. The `account`
  property in `user` is given special treatment. If `account` has an `id`
  property that can be retrieved via `bedrock-account`, then we only store the
  `id` in the session database and rely on persistent storage of the account
  for later retrieval.

  If an `account` is set but there is no such account in `bedrock-account`,
  an error is thrown. Non-persistent accounts are not presently supported.
  */

  const dataToSave = {};
  if(user.account) {
    const exists = await brAccount.exists({id: user.account.id});
    if(!exists) {
      throw new BedrockError('Account not found.', 'NotFoundError', {
        id: user.account.id,
        httpStatusCode: 404,
        public: true
      });
    }
    // only persist account ID, rest of account persisted by
    // `bedrock-account`
    dataToSave.accountId = user.account.id;
  }

  return dataToSave;
}

// exported for testing purposes only
export async function _deserializeUser(data) {
  /* Here we populate the `req.user` property used by express routes with
  information from the session. The `data` object was populated with whatever
  information was previously stored in the session database for the current
  session ID. This data needs to be translated into a `user` to be set to
  `req.user`. If `accountId` is present, it is assumed to be an account ID and
  we populate `user.account` using the account associated with that ID by
  using `bedrock-account`. */

  const user = {};

  // backwards compatibility; old format used `data.account` to store the
  // account ID; new format uses `accountId`
  const accountId = data.accountId || data.account;
  if(typeof accountId === 'string') {
    try {
      const record = await brAccount.get({id: accountId});
      if(record.meta.status === 'deleted') {
        throw new BedrockError(
          'Account not found.', 'NotFoundError', {
            httpStatusCode: 404,
            public: true
          });
      }
      if(record.meta.status !== 'active') {
        throw new BedrockError(
          'Account is not active.', 'NotAllowedError', {
            httpStatusCode: 403,
            public: true
          });
      }
      user.account = record.account;
    } catch(e) {
      if(e.name === 'NotFoundError' || e.name === 'NotAllowedError') {
        throw e;
      }
      // make other errors private
      throw new BedrockError(
        e.message, e.name, {public: false, id: accountId}, e);
    }
  }

  return user;
}

function _isCrossOriginAllowedHost({req, options}) {
  // presumes that `_maybeFormOriginated(req)` already ran and ensured the body
  // was empty or "simple", only empty is permitted here w/allowed hosts
  const {allowHosts} = options;
  if(!allowHosts || req.body ||
    !PERMITTED_ALLOWED_HOSTS_METHODS.has(req.method)) {
    return false;
  }

  const allowed = new Set(
    Array.isArray(allowHosts) ? allowHosts : [allowHosts]);
  return allowed.has('*') || allowed.has(req.headers.host);
}

function _maybeModernCrossOriginRequest(req) {
  if(req.headers.origin === undefined || req.headers.host === undefined) {
    // not a modern browser; they all send `origin` and `host`
    return false;
  }
  // return false if host header does not match host parsed from origin
  return req.headers.host !== (new URL(req.headers.origin)).host;
}

function _maybeFormOriginated(req) {
  return !req.body ||
    req.is('urlencoded') || req.is('multipart') || req.is('text/plain');
}
