# bedrock-passport ChangeLog

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
