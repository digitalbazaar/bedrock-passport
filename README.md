# bedrock-passport

A [bedrock][] module that adds website or REST API authentication to
[bedrock][] via [passport][].

## Requirements

- npm v3+

## Quick Examples

```
npm install bedrock-passport
```

```js
const brPassport = require('bedrock-passport');

app.server.post('/resources/:resourceId',
  brPassport.ensureAuthenticated,
  (req, res, next) => {
    // resourceId available with req.params.resourceId
    // user account available with req.user.account
    res.sendStatus(204);
  });
```

## Configuration

For documentation on configuration, see [config.js](./lib/config.js).

## Authentication

There are a number of ways a client may authenticate itself with the REST API.
These methods include:

- Website session based on user and password and using cookies.

### Cookies

This method of authentication is useful for clients that are under your control
and who you trust with your password to the service.

## API

### authenticate({strategy, req, res, options = {}})

Attempt to authenticate a user using the specified strategy. If authentication
is successful, a `bedrock-passport.authenticate` event is emitted with an
object with this format:

```js
{
  strategy,
  options,
  user
}
```

Once all event handlers have run, a promise resolves with `{user}` data.

### authenticateAll({req, res, options = {}})

Attempt to authenticate a user using all configured strategies. For every
authentication method, `authenticate` will be called. If more than
one authentication method is configured to run automatically, all of the
associated accounts must match.

### createMiddleware({strategy, options})

Creates express middleware that calls `authenticate` using the given strategy.

### optionallyAuthenticated(req, res, next)

Express middleware that processes a request has been optionally authenticated
via `authenticateAll`. Code using this call can check if the request is
authenticated by testing if `req.user` and `req.user.account` are set.

### ensureAuthenticated(req, res, next)

Express middleware that ensures a request has been authenticated via
`optionallyAuthenticated`. Redirect if not and it looks like a browser GET
request, otherwise set a 400 error.

[bedrock]: https://github.com/digitalbazaar/bedrock
[passport]: https://github.com/jaredhanson/passport
