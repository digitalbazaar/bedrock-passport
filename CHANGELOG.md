# bedrock-passport ChangeLog

## 9.0.0 - 2022-04-06

### Changed
- **BREAKING**: Rename package to `@bedrock/passport`.
- **BREAKING**: Convert to module (ESM).
- **BREAKING**: Remove default export.
- **BREAKING**: Require node 14.x.

## 8.1.0 - 2022-03-25

### Changed
- Update peer deps:
  - `bedrock@4.5`
  - `bedrock-account@6.3`
  - `bedrock-express@6.4`.
- Update internals to use esm style and use `esm.js` to
  transpile to CommonJS.

## 8.0.3 - 2022-03-09

### Fixed
- Allow old sessions (prior to serialized user data format change) to be loaded.

## 8.0.2 - 2022-03-07

### Fixed
- Surface not found / not allowed errors when loading session account.

## 8.0.1 - 2022-03-07

### Fixed
- Ensure errors are thrown when account status is not `active` on session load.

## 8.0.0 - 2022-03-07

### Changed
- **BREAKING**: Use `bedrock-account@6` which removes `bedrock-permission`
  including concepts such as `actor`.
- **BREAKING**: Remove deprecated callbackified functions.
- **BREAKING**: Updated peer dependencies, use:
  - `bedrock-account@6`
  - `bedrock@4.4`
  - `bedrock-express@6.2`

## 7.0.0 - 2021-10-08

### Changed
- **BREAKING:**: Upgrade to `passport: ^0.5.0`.
- **BREAKING:**: Upgrade Peer Dependency to `bedrock: ^4.0.0`.
- **BREAKING:**: Upgrade Peer Dependency to `bedrock-express: ^5.0.0`.
- **BREAKING:**: Set `engines.node >= 12.0.0`.

## 6.1.0 - 2021-01-12

### Changed
- Update bedrock-account@5.0.

## 6.0.0 - 2020-06-29

### Changed
- **BREAKING**: Remove support for `bedrock-identity` module and
  `req.user.identity`.

## 5.0.2 - 2020-01-10

### Fixed
- Return account ID (not identity ID) in error details.

## 5.0.1 - 2019-11-13

### Changed
- Update dependencies.

## 5.0.0 - 2019-09-11

### Changed
- **BREAKING**: Remove HTTPSignature strategy.
- **BREAKING**: Remove DID strategy.

## 4.0.4 - 2018-09-18

### Fixed
- Add missing `await` in `authenticateAll` API.

## 4.0.3 - 2018-07-26

### Fixed
- Ensure user authenticated before checking for account existence.

## 4.0.2 - 2018-06-25

### Fixed
- Fix bugs related to calling `passport.authenticate`.

## 4.0.1 - 2018-06-25

### Fixed
- Use `brIdentity.getCapabilities` to produce identity-based
  actor.

## 4.0.0 - 2018-06-18

### Added
- Support promises for `authenticate` and `authenticateAll`.
- Include `strategies` and `identities` in `user` (and therefore `req.user`).

### Changed
- **BREAKING** Use named parameters in public API.
- **BREAKING** `authenticate` no longer create an express middleware, use
  `createMiddleware` for that.
- **BREAKING** `checkAuthenticate` has been changed to `authenticateAll`.

### Removed
- **BREAKING** `info` is no longer used or returned in authenticate events.

## 3.4.2 - 2018-02-23

### Changed
- Update to support http-signatures "(request-target)" as well as the older
  "request-line".

## 3.4.1 - 2017-09-04

### Fixed
- Support node 6.x (no WHATWG URL parser for origin).

## 3.4.0 - 2017-09-04

### Added
- Allow full `origin` to be used for `domain` when
  performing DID-based authentication.

## 3.3.0 - 2017-06-27

### Changed
- Upgrade `bedrock-key` peer dependency from 3.x to 4.x.

## 3.2.1 - 2017-04-14

### Changed
- Add validation of public key document in `HttpSignatureStrategy`.

## 3.2.0 - 2017-02-13

## Added
- Add `bedrock-did-client` dependency and config. Use of
`bedrock.config.passport.strategies.did.didio.baseUrl` is deprecated.  Use
`bedrock.config['did-client']['authorization-io'].didBaseUrl` instead.

## 3.1.9 - 2017-01-17

### Changed
- Improve error handling in `deserializeUser`.

## 3.1.8 - 2016-11-10

### Changed
- Utilize `exists` API.

## 3.1.7 - 2016-09-21

### Changed
- Restructure test framework for CI.

## 3.1.6 - 2016-08-24

### Fixed
- Remove .only from test spec.

## 3.1.5 - 2016-08-12

### Changed
- Add validation for dereferenced documents.

## 3.1.4 - 2016-08-11

### Fixed
- Only authenticate active identities.

## 3.1.3 - 2016-08-05

### Fixed
- Fix uncaught error in HttpSignatureStrategy.
- Fix mocha test suite.
- Include domain information in error details.

## 3.1.2 - 2016-06-15

### Changed
- Move passport authentication after any static file middleware.

## 3.1.1 - 2016-05-19

### Fixed
- Fix bug w/improperly setting the shared `callback` closure var
  in `authenticate`.
- Fix passing strategy options when using `createAuthenticator`.

## 3.1.0 - 2016-05-13

### Added
- Optionally disable logins for non-persistent users.

## 3.0.5 - 2016-05-09

### Fixed
- Ensure `bedrock-passport.authenticate` is emitted when using session authN.

## 3.0.4 - 2016-04-28

## 3.0.3 - 2016-04-26

## 3.0.2 - 2016-04-15

### Changed
- Update bedrock dependencies.

## 3.0.1 - 2016-03-16

### Changed
- Add public key lookup for HTTPSignature keyIds that are dids.

## 3.0.0 - 2016-03-02

### Changed
- Update package dependencies for npm v3 compatibility.

## 2.0.1 - 2016-02-01

## Changed
- Support non-persistent users in HttpSignatureStrategy.

## 2.0.0 - 2016-01-31

### Changed
- **BREAKING**: Modular redesign.
- **BREAKING**: Better extensibility and configurability.

### Added
- Minor CSRF protections. When using authentication middleware, session-based
  authentication will only be counted as valid under certain conditions. If
  the request does not contain a urlencoded (single or multipart) body
  (unless explicitly permitted via the middleware options) it will not be
  counted. If an `Origin` header is in the request but its host value does not
  match the `Host` header and the method is not GET, HEAD, or OPTIONS, it will
  not be counted.
- Strategy for authenticating via DIDs.

## 1.0.1 - 2015-05-07

## 1.0.0 - 2015-04-08

## 0.1.1 - 2015-02-23

### Added
- Support for `bedrock-express` 0.2.x.

### Changed
- **BREAKING**: `bedrock.HttpSignatureStrategy.*` error types renamed to `HttpSignature.*`.

## 0.1.0 - 2015-02-16

- See git history for changes.
