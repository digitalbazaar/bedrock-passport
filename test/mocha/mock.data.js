/*!
 * Copyright (c) 2015-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const helpers = require('./helpers');
const {config} = require('bedrock');
const {constants} = config;
const fs = require('fs');
const path = require('path');

constants.SECURITY_CONTEXT_V1_URL = 'https://w3id.org/security/v1';
constants.CONTEXTS[constants.SECURITY_CONTEXT_V1_URL] = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, '../contexts/security-v1.jsonld'),
    {encoding: 'utf8'}));
constants.SECURITY_CONTEXT_V2_URL = 'https://w3id.org/security/v2';
constants.CONTEXTS[constants.SECURITY_CONTEXT_V2_URL] = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, '../contexts/security-v2.jsonld'),
    {encoding: 'utf8'}));
constants.IDENTITY_CONTEXT_V1_URL = 'https://w3id.org/identity/v1';
constants.CONTEXTS[constants.IDENTITY_CONTEXT_V1_URL] = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, '../contexts/identity-v1.jsonld'),
    {encoding: 'utf8'}));

const data = {};
module.exports = data;

const identities = {};
data.identities = identities;
data.keys = {};
data.owners = {};

// user with a valid 2048 bit RSA keypair
let userName = 'alpha';
let keyId = '31e76c9d-0cb9-4d0a-9154-584a58fc4bab';
identities[userName] = {};
identities[userName].identity = helpers.createIdentity(userName);
identities[userName].meta = {
  sysResourceRole: [{
    sysRole: 'credential.user',
    generateResource: 'id'
  }]
};
identities[userName].keys = helpers.createKeyPair({
  userName: userName,
  userId: identities[userName].identity.id,
  keyId: keyId,
  publicKey: '-----BEGIN PUBLIC KEY-----\n' +
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwzPDp8kvJlGHbQGHQGcp\n' +
    'tO5iZG8iwED1QFNvJuKTZqYDoN44LUf95tYsjGqT38qj2/uo4zZRkfE3H1TEnsDo\n' +
    'KbbRn1mqV3098sU/G9Kk8fsXL9eJrQ77sLoDQmZf0/huIqHw6/jN7m5p3bq80A0m\n' +
    'gaJ56FuMq6IM4b9Sw40ajXTWQdiJqThN41eSHK01peT9jHMlnbQQwolqw0y9fkZ5\n' +
    'oEGHezQH6+CVRXB2u7WveMWvow3+ssGDwoK6/YeSWUXFv0VZoQwVO0VmaIFcM11f\n' +
    'G3KZD+iAayrF3xXz8ZPe0PY+6nZZi5/4HNy6B/30hAQn9X9I/0WMmmbQ5gCHJsu9\n' +
    'WwIDAQAB\n' +
    '-----END PUBLIC KEY-----\n',
  privateKey: '-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIIEpAIBAAKCAQEAwzPDp8kvJlGHbQGHQGcptO5iZG8iwED1QFNvJuKTZqYDoN44\n' +
    'LUf95tYsjGqT38qj2/uo4zZRkfE3H1TEnsDoKbbRn1mqV3098sU/G9Kk8fsXL9eJ\n' +
    'rQ77sLoDQmZf0/huIqHw6/jN7m5p3bq80A0mgaJ56FuMq6IM4b9Sw40ajXTWQdiJ\n' +
    'qThN41eSHK01peT9jHMlnbQQwolqw0y9fkZ5oEGHezQH6+CVRXB2u7WveMWvow3+\n' +
    'ssGDwoK6/YeSWUXFv0VZoQwVO0VmaIFcM11fG3KZD+iAayrF3xXz8ZPe0PY+6nZZ\n' +
    'i5/4HNy6B/30hAQn9X9I/0WMmmbQ5gCHJsu9WwIDAQABAoIBAESCMWP8xvCC4q3O\n' +
    'QILI8ilPFPc8zgx9f9XAsp0KHkODdniKJVs3DhRrDJ2Hdjiv7Qxy6ZY85Sn8Z6U2\n' +
    'Yf95osGpKS7tEEy+ZvSCZ6DDMCLBRiUDV42GWa1vy18NgQprAXRkM6MN4nCRDdTF\n' +
    'CilWxDHxLSnwn5FJQY4lUM3TAwOr5fBvSxjZiwDimykyy90wSqQxl1HI/badNipJ\n' +
    'ZDCoVdIDFtYjjD03o7wsyOPFxD0sZnKnxSIS8kYeHMxK5Js20eLdHRocZdSebxbu\n' +
    'bESUWaLg0sFn1tBg4y19hflAqzJGpta2wUombipkLm3DLJWQVMeq/52WJf7oqhr9\n' +
    'Fg1BxkECgYEA4JQ6i+XSxMkZnsk0vCjEEQH+lfixV9+dQ9tBmn+FqNKTV40gix8+\n' +
    'CMnB/ZKT6CknByQ1EojX7ZDj/c1qgoVYyRkcYcoQGzDwxZLydQpCncPT5/UYic0H\n' +
    '8eKUCQLzwOnZo55mBmehxTqTwmtYjoSCWsGWoGO7ssEGSa+rIYd4SqECgYEA3oNX\n' +
    'z53tE+Y8b7G95DEZIom32NpreMVq9T0xS8ZUYeDkR80a3Mli6IHz+qbFSd2ylcNf\n' +
    'PbnJ1xeEGyGgMi9PG4E7GWTitl68uAOKnZ/83nHNtXQ5SJwRtxPiOyuh+HN8AAqX\n' +
    'PfNCDffF6gAm+wfxyY1aAL04aBmzaaqEWpEGonsCgYEAxUqzHE+sl+ArN8l/IIWX\n' +
    'qXFdHJc8BPyXhhNKUNYSr7s+Yb3DhzTNJJ9KYt+wPFZayPVQApZhS3zsLf2VwlAv\n' +
    'LYt32ZjQCXM3MfrkMVnwJ/TvZml1Qynx/teUQU5soV9PKWRwMNQ906ygPj5br+hN\n' +
    'NDm5f/Hd5S2ZvoYrCuueC8ECgYEArKTZ3/PXu6Xa5IrTHBdgOiUCqVWnJ1h9iXQG\n' +
    'KJXkaOEWHgOswPvcKyyRQbxdvNcvtfWVkw3w5luPm4F2ixmb1mppkWVuZjORV3Ef\n' +
    '/vbgOzOveQeJXqYBNLxPvrs2+8+WuW1+NYnliXLic5HUrNdYKZrr50DpYBP42ZZ9\n' +
    'BMwbirsCgYA01XR+CS661Vy8bh6dEHa1IDoWBk3gqk9REUFnhdYLLEXy3zi1SnfI\n' +
    'mXm+fICVKinK5jKA/iu0M1zLUY/rWjpIWQTMpk9AcLhWYwURPCkLw/E//T5iaw37\n' +
    'cuRO/K57URWU78bQYpTMSCs0JhXnvHN1iCM5xyZ6rtz0jwZheWe+sA==\n' +
    '-----END RSA PRIVATE KEY-----\n'
});
data.keys[keyId] = createPublicKeyDoc({
  keyId: keyId,
  publicKeyPem: identities[userName].keys.publicKey.publicKeyPem,
  userId: userName
});
data.owners[userName] = createOwnerDoc({
  keyId: keyId,
  userId: userName
});

// the public key and private key here do not match
userName = 'beta';
keyId = '16918840-a3b8-4619-b16e-1a51a633dc86';
identities[userName] = {};
identities[userName].identity = helpers.createIdentity(userName);
identities[userName].meta = {
  sysResourceRole: [{
    sysRole: 'credential.user',
    generateResource: 'id'
  }]
};
identities[userName].keys = helpers.createKeyPair({
  userName: userName,
  userId: identities[userName].identity.id,
  keyId: keyId,
  publicKey: '-----BEGIN PUBLIC KEY-----\n' +
  'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3gxZF06Sz9EDEA8cEDBk\n' +
  'jqDAjI7LUL49/e0plHIdpFp5NSIiHYqFl+fb0Ah0XsliJ9VpW4MEHdqRkD4jvUnr\n' +
  'hQLWjUvVvxMQ7h7mdu+GuN7jYwPf37qtJ/CzDBKUs+tult/ZbehKSKSnKA2eKrR3\n' +
  'eahElcjKP3rSgzza6GEZv2+M36PmNvmmNIYAqhQPwW+DWHjqWkz5LkzCFRGkT6Gf\n' +
  '/h279giI3ns+tvppzLtq8/TP8rPS9ZX6IejktZu7/Pk8BMwta8Mwi3CAncLBzaj4\n' +
  'UkF0Bvzzs6joaAsrB33Y48TkHYCddKa0k8abykiWsWjCIZ1wr/Y7vqmenH5YbVq3\n' +
  '3QIDAQAB\n' +
    '-----END PUBLIC KEY-----\n',
  privateKey: '-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIIEowIBAAKCAQEAuxkWX5k9tUjdMRiV2hTrpj+uHb++liyhWVGH7KHIOhfZwMHf\n' +
    'JpmLeRplUpcO5Fp+ob1XCEyU9iUt5MBGJbt6kB7u9yaGU00mwqtpz2HYkUF2gAV2\n' +
    'PYyrdDid+bw/e7Rj+GkJLalgI1spmE8kgHQQZNUEmL7xFxSU6ODb9/lr7o0SbwA6\n' +
    'clOcpgfKYKP4GLd5Jb/gPqj+S+xw1R3HiuH6NTChUvJPQNh0PsZRKpoMP61Vqujt\n' +
    'w3ozm+eqwBJPCJOGUEjiqzMINVIZ66ZeUdVDO6tEnOyQIda4JFq/bzJdRPwCUf/Z\n' +
    'hju0d3qG7gMF2TQoYXrh4kblxXd4aXHlntnneQIDAQABAoIBAEoezzFCOSMXYaFw\n' +
    'lvUVcqGi+qyIaM1/ktAar5l8IiF5j2eAppHZJFrurRNCCsFGZIJYyyDbjevRoNPN\n' +
    'pDyQgCaWSp8Y4QAhQWi/laR1o+EvqO1gvI33q3jYcSUdgZzVQwGHQv6W6iI3nEvd\n' +
    'lp1Y3aHEjhShGEvHeJKleh9L7YlMJkxrmwrB5JimUoVYw4qi1xYPJG+glliitXpQ\n' +
    'J4ZJndDwi8/hMXj0Jp6Y+ZbkIey538G2pYP+w8PpDwkUQiVRlnBneAD9hKgfQFOs\n' +
    'VhMK42QNL4o7wGNmL3wiCHuLybUI6cyaqaT5pEglLUf/oAEPtYboWR7///1fTR/d\n' +
    'zABgpv0CgYEA5pQt8rKf4ClvOaAWHpgEFIbNPoiNg5xVjshDZrE6P8Ut1q+g1Lgd\n' +
    '1TzTUBEX29vqw9EbKf1clT1Z9FhxDeCeLK39imzgMMFK0PETkmU/rO662qFpRPkJ\n' +
    'gJwKgcMEri/FMx9azmG00v9DJKtZyRrwmEjLaj9dgi3+AC9BNdMBBV8CgYEAz7m2\n' +
    'O7xNDH8rlseuIgpJOKfCsknht/HtnLGFko0R2jim+dgmK1NmIiaLXK6voGcdTuoA\n' +
    'BRTYtUmhydP4gUz+8kyevPXx1zDIbAXMMfktGC3z5g8VHBhg9oz7aFyI+hTIs8qQ\n' +
    '3fySEcvlLN2icY62CKkjbD6Sv2f0lDqELx5/qicCgYEAyGuCaNOUnd7GG/unXl5a\n' +
    'JZFqc3F0ODK6N4qg83EXJXj5uAMes+d5nvDo6E6DQ4qrTBvFFcFxKROTzgzV7+8O\n' +
    '7d0qZZjvYdGRe34guf4h0+oKJqFohBhHhy+a/mGJ/vHs4dveLUfGSiSwsv3x5Bjz\n' +
    'ihq0HR0I5W+euYBZmTRYTdcCgYBaX+ECEkWvVzC+s/d1xeXfaVWSvgQfRHltf+qu\n' +
    'PQP0Xkt/TeQlW26HEx/03ed5MQOWTsZdb5ltHjDun3Nxxe7xuhYh/hsO1aGNJeSW\n' +
    'JWPSLkP75rn3dD/TZLkIyaGqtBox5sKqYfWnGn+FypOfNkjKcdQAhyTPc8n8J41U\n' +
    '9r7yZwKBgDPElVr1Hk79sVGEW+iEN7+v9SD9BPvyuw71wJeimekjCd5NPODepaMq\n' +
    'oaJS1K9kuYl7f9qdHwXhiZuoZx2BuFl1eSV5EvfMQwXrrmOemV6PDilKmNqBeS4P\n' +
    'iySZfMxYEzjbyzDrsnKyjuZ5rUMYn2VenyhYZlsGgIRVZnqnDQFP\n' +
    '-----END RSA PRIVATE KEY-----\n'
});
data.keys[keyId] = createPublicKeyDoc({
  keyId: keyId,
  publicKeyPem: identities[userName].keys.publicKey.publicKeyPem,
  userId: userName
});
data.owners[userName] = createOwnerDoc({
  keyId: keyId,
  userId: userName
});

// gamma does not have a key document
userName = 'gamma';
keyId = '6eda57cb-aa0b-441c-8f27-0aeab242ee91';
identities[userName] = {};
identities[userName].identity = helpers.createIdentity(userName);
identities[userName].meta = {
  sysResourceRole: [{
    sysRole: 'credential.user',
    generateResource: 'id'
  }]
};
identities[userName].keys = helpers.createKeyPair({
  userName: userName,
  userId: identities[userName].identity.id,
  keyId: keyId,
  publicKey: '-----BEGIN PUBLIC KEY-----\n' +
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxaUDQ0PO7ufGQF/pR5Gq\n' +
    'sRA74OvVX6nHjBZ2A2KS6EnhrSj8KZKrybPYlPE6josd1AZbNqYLJZy+WK3Hv/JH\n' +
    '/fGs4wtfitP3AZF/PkIMqTBlo0W6RtXMT046343xG6rkq39xcSaHpubGfjHP2hmF\n' +
    'Xt9gb1QbznAENuXv/v8UGyCyX6f0dyxknZVVaIIZdA0w2SeRBdGOy46jte8dBS14\n' +
    'seZIPioN+l0rTvsv7WbVAtQ3TSGFAc51ShWDGaEY68MwZTJqUzVOla8jxgoNGI+n\n' +
    'O5gTc8+ihh2TaK/8vfUqL4l6ti+naT0UwCMQjfsjhoz5G0At7pNXttkFrZUfW5zo\n' +
    'cwIDAQAB\n' +
    '-----END PUBLIC KEY-----\n',
  privateKey: '-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIIEowIBAAKCAQEAxaUDQ0PO7ufGQF/pR5GqsRA74OvVX6nHjBZ2A2KS6EnhrSj8\n' +
    'KZKrybPYlPE6josd1AZbNqYLJZy+WK3Hv/JH/fGs4wtfitP3AZF/PkIMqTBlo0W6\n' +
    'RtXMT046343xG6rkq39xcSaHpubGfjHP2hmFXt9gb1QbznAENuXv/v8UGyCyX6f0\n' +
    'dyxknZVVaIIZdA0w2SeRBdGOy46jte8dBS14seZIPioN+l0rTvsv7WbVAtQ3TSGF\n' +
    'Ac51ShWDGaEY68MwZTJqUzVOla8jxgoNGI+nO5gTc8+ihh2TaK/8vfUqL4l6ti+n\n' +
    'aT0UwCMQjfsjhoz5G0At7pNXttkFrZUfW5zocwIDAQABAoIBAAcLerJLGHUrjcV9\n' +
    'pbMHXi4xhfDedxyR0KsNoec8/D+LYp/pdhOFRtpJrs6gSpYKH2YPU/D+uib9D0vZ\n' +
    '5eTRnf9PPfpZzW4FYCiOJxrw/8KIFxdaxOkBdebdwvt088MotD3orQJ7fRpV331g\n' +
    'CSidAEQBck6FkPgqxfuu9n8AWJce4y+9fsWL/384xkvxRNbwWEUHElgEJVWw8rcN\n' +
    '2daNQ4IcQvaHPHAb8u5hngQeE54Uk1ayJtNun6ycgcNbAcSMsFkHn3Df1bm3FHBx\n' +
    'SvvyGCK4s3nrE/g7nM8exjEMOZq3OgaqImg85dwkMkOBFG4wS1IPQxM3GH++3WPa\n' +
    'yPPQVgECgYEA6vs2jcY4+k+v9+cfsA5TK8ogrWjGXnq13QNaElTMEyJ779Ivn89T\n' +
    'TmEbrI+1LL4oEJj3F3Cybb5TSczV/TKrxvIyA03YlbmojWs8oVB3iGAIaG612LmH\n' +
    'maVWgbYrpobEUhq2KYK/MX8+oDYRSnUzz3w1cgYo+I7lkr1+i7ko2YsCgYEA11LV\n' +
    'gmmiNHjTOeuDpB1EoIZU/ELoaRnNVZn446GTJMCJWd6WKPrG5lFR4WwmSgEk+2Lo\n' +
    'EcbeUbZCZudy4Ce58ZbzMz2NGEBSL9Tp+hyUKpqXwYcDOafPST6SwvC6Uc2AQWLo\n' +
    't4DeiNaVtaLxvti4jw/a1C8w+nYMT5JCwyFvebkCgYBgDg0A63TDLev65KnZaCGr\n' +
    'ltbAzEG6wWKyU/pv3+YENGaBZGQ/aZreQWf0pFIlVh4+mqj3FgR6RAD7/BXFiP8b\n' +
    'Nkone5z7p4c1OA7yylfykX8eYZNIYp8Bucqg/3zcd96syWqJkX7iludcyn1K+JoT\n' +
    'SOz4DXiWEqPZ1khyiWAffQKBgQCfm4weXjTZFlLkVRpAVV2ga9KlJudluLWG5Voj\n' +
    'SYprrLhjQGYoPDOhV9gM84CyTITgPqFtQ+9ZvHMeGiQB2hCv7seZTN/AgTUqtXU2\n' +
    'a2a86djhoDWY0DYLwfFBxPUnW9/dF/cOxtytq/pPKFhvse+kRAleTRjOHyDi/rS0\n' +
    'NZ2PKQKBgGXtGHmjQQh0+l6LKajGlzjLcJC86WXXJRw+DpeMtgQyn7ePvmp1lQIO\n' +
    'GB9lmoNH5iZMyJhtlg/yl80qOQ9XUQ172GEfQY6H1QEB5mC61FXVJ5oK0dEJPm//\n' +
    'EWpnCmxX8b3hWmm10fQSp274DnLQhhKRGJS6mxRcHltpKWpHgrYS\n' +
    '-----END RSA PRIVATE KEY-----\n'
});
data.owners[userName] = createOwnerDoc({
  keyId: keyId,
  userId: userName
});

// delta does not have a published owner doc
userName = 'delta';
keyId = '9a1ff4d2-010a-4152-9bf1-e8618f1c8e82';
identities[userName] = {};
identities[userName].identity = helpers.createIdentity(userName);
identities[userName].meta = {
  sysResourceRole: [{
    sysRole: 'credential.user',
    generateResource: 'id'
  }]
};
identities[userName].keys = helpers.createKeyPair({
  userName: userName,
  userId: identities[userName].identity.id,
  keyId: keyId,
  publicKey: '-----BEGIN PUBLIC KEY-----\n' +
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2ASiyri3swbNDk8ShXFf\n' +
    'xCEufyhZPNpxEaTPi7/1AmO969PfBLwD8vnEqtCkuBC4QknQTqh/02YlBsoZoXC9\n' +
    'F/cLwRWl1HGdsXlRCn4vGCq5Oo4NAZgE0YEL81nagVISdZ433kXSdKWJPNCMc5s5\n' +
    'GdUsEhrkK1FEBFn2mhbodCZTayC6S9n6N0BbJE9y37sYE2M234YIMvj0enmpdoM4\n' +
    'OOM2KblajIFmpQeTeSK+VbQa63tUiQgiv+RtOzQHA6bfbUzKQtWSffB6T0FnH+zy\n' +
    'COiTDtaewO6dqcXtDSQwRQTRwXIavlmDPZg5z5U+UTwhN9Sm1BdVD0vcWEBykUDN\n' +
    'ZQIDAQAB\n' +
    '-----END PUBLIC KEY-----\n',
  privateKey: '-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIIEpAIBAAKCAQEA2ASiyri3swbNDk8ShXFfxCEufyhZPNpxEaTPi7/1AmO969Pf\n' +
    'BLwD8vnEqtCkuBC4QknQTqh/02YlBsoZoXC9F/cLwRWl1HGdsXlRCn4vGCq5Oo4N\n' +
    'AZgE0YEL81nagVISdZ433kXSdKWJPNCMc5s5GdUsEhrkK1FEBFn2mhbodCZTayC6\n' +
    'S9n6N0BbJE9y37sYE2M234YIMvj0enmpdoM4OOM2KblajIFmpQeTeSK+VbQa63tU\n' +
    'iQgiv+RtOzQHA6bfbUzKQtWSffB6T0FnH+zyCOiTDtaewO6dqcXtDSQwRQTRwXIa\n' +
    'vlmDPZg5z5U+UTwhN9Sm1BdVD0vcWEBykUDNZQIDAQABAoIBAGmRem1P8JaRUE0Z\n' +
    '35dPXNngzXRfJ51Rs8hHnxZQ7VAJpptFo8wQhm2MGszPwnAh26qpoB+QwUdyt82l\n' +
    'nvkCu6ammRv3lF9KVyKQg0Z5fFJ3LqarHTgWLuSkCE8ZLmvczCCm/e6meL+A1pzd\n' +
    '3oXw6erx/uOqOK/iuzbVMGsFnvyDiEU0Xlf5RiNHUMN6yD+ziGAFFniGD+EjG8ye\n' +
    'DwUwYcci50z8M/fn/Gu30z9/+3rNyBbdqg7pIqeWGcvfTqnl7GWcccVpY/NB5/NQ\n' +
    'NYKb4+vjOxKAOdcWP+moYNVlixrKJey/zGxuAuGQ8Klla98FIloVFq3IiezSfG7o\n' +
    'ad23INECgYEA90HTJsjQGK8ZKm+6Mcv6dpL7F0AiaIlCnGCSoxSEqAc2cKZaBtts\n' +
    'Bj5ttXMT2nC5my85VVrrjEV2eAQljPSs2jm9pDlJPEcod+jD/xKWxY0OYpslAI5z\n' +
    'rynIEnOybK0h5UWLaljaBUf+68bCTu2O2aEu8eMJ9TV3DKtidPSEZscCgYEA36gI\n' +
    '98X9tvkAshLndNob0IEI07VJJcq/Wk83iIwCqfej5VODo7eCn1L335BPtKZFc0LY\n' +
    'k+CeMJwO3K0/kMfuG77SlSAQLbND+KOefay0ug7FQYLaqtTluegfRtesx8drNvzU\n' +
    'nZApRNxXpgC36JuWgS0k4qut4FXpU8XEPzvaTnMCgYEAjqUyHREDRQpXeW0FvU7R\n' +
    'i3DWXR6J+0cc37yzPFRNB+dJWAoQrB4QnzWK84CVdpNL8SR4bi7K75zvcOPriftq\n' +
    'cWeYadMG1jizNyJZWKGvy/7Jysd4vG5yfR6cp1CKIjpr8KqDePITrbJQdlOvq/tP\n' +
    'S2y6+Z+jEg0rRmrlnVWnwOcCgYAHhYMnsgTiTmVzl6cpCty8mlpNpF8dYkAlLVzU\n' +
    'vsCoLqfYYoKe0uEVspibcCL+FElpoundr0Qiplzplvn4SID9deFnGnjw0IKMrhP6\n' +
    'bgB18WE43smzzQ0cv22t2Dr7TP2SD9ampd59bluUPZnxvKnHFlmTNerXDIyYQKJk\n' +
    '7gJdeQKBgQD1yuP9Gdiivqwfcs9JLI0zdTebFbwe0ARLiXvG5ja5sChlSIVmNKNz\n' +
    'F/EF7zWGowvnwn4POY/ahw6WR/ChVXKi9V4taQ48vSybXRoWVPGmQYnSqGkD+TX8\n' +
    'gOI3+STK6hchhb5a1pX0w5ZlzEwT0f9DGj8tF88Ihz+I8C+Oz7Zvsg==\n' +
    '-----END RSA PRIVATE KEY-----\n'
});
data.keys[keyId] = createPublicKeyDoc({
  keyId: keyId,
  publicKeyPem: identities[userName].keys.publicKey.publicKeyPem,
  userId: userName
});

// epsilon owner doc has public key ID for alpha owner
userName = 'epsilon';
keyId = '9a1ff4d2-010a-4152-9bf1-e8618f1c8e82';
identities[userName] = {};
identities[userName].identity = helpers.createIdentity(userName);
identities[userName].meta = {
  sysResourceRole: [{
    sysRole: 'credential.user',
    generateResource: 'id'
  }]
};
identities[userName].keys = helpers.createKeyPair({
  userName: userName,
  userId: identities[userName].identity.id,
  keyId: keyId,
  publicKey: '-----BEGIN PUBLIC KEY-----\n' +
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApqbflcCpm+6ufHVa5oHg\n' +
    'm7cHTELcVrV7uJpc/pU2p1n8EzXnhBRZDJZBYOApz9P21/IzBYtZWoUDzl44aZim\n' +
    'rEwR6sRm0YNblVntvVizFrzs1v3GzThXSjvvdykBUhbI3oOSEYAmf4zvOUQmARHx\n' +
    '05uVxsP6Y6P/GV0TYj0S0NlU6WYhKZC+6jl8a+rDvvrQpi1NiphQ+udOtfzkxNJW\n' +
    '6Zs1jd7Bd8KdzPN2ON5R2LhUhA2/z0Z3oTddPAeLEPuEIxR9h/8ot8rOzmT5+va5\n' +
    'ulQHfYbNX7NGogSNgjul2X+ULH3PgWEBocHm463MiYYg7hGsOJaUvDggQU8z4ROu\n' +
    'uwIDAQAB\n' +
    '-----END PUBLIC KEY-----\n',
  privateKey: '-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIIEowIBAAKCAQEApqbflcCpm+6ufHVa5oHgm7cHTELcVrV7uJpc/pU2p1n8EzXn\n' +
    'hBRZDJZBYOApz9P21/IzBYtZWoUDzl44aZimrEwR6sRm0YNblVntvVizFrzs1v3G\n' +
    'zThXSjvvdykBUhbI3oOSEYAmf4zvOUQmARHx05uVxsP6Y6P/GV0TYj0S0NlU6WYh\n' +
    'KZC+6jl8a+rDvvrQpi1NiphQ+udOtfzkxNJW6Zs1jd7Bd8KdzPN2ON5R2LhUhA2/\n' +
    'z0Z3oTddPAeLEPuEIxR9h/8ot8rOzmT5+va5ulQHfYbNX7NGogSNgjul2X+ULH3P\n' +
    'gWEBocHm463MiYYg7hGsOJaUvDggQU8z4ROuuwIDAQABAoIBAEwFg6kEolqHnwEX\n' +
    'Z8gPJy7hZ2radTj4wN+NSy63Up805VC+HkaaIaUkRd6zY19zCf+odK3qy3AHjZzu\n' +
    'Tj2dbSrb6LB3t4+LpJOU2matt8R/mmrYiX/EW815Wdu50OhpjGg1DMT++JDm8Znm\n' +
    'BJAoZ3BoYQKzE92wSgZ/9v+xbIvoW9MB0t/VfJodn4yKXDlHtLpcytKJhL62667a\n' +
    'vGcibV9/dk3Ejav8Dv+zxhk7JoUkzo/f3sjzXQWZ0N8peyFjw5hEyeDz3GOMGd4U\n' +
    'sTz0qKwjRA3Vcytps+dY1sYnC/V8bAJuuwy65wSXref4xO7PhcNSV7Hn8Oy80vuz\n' +
    'tm9M3sECgYEA1PFVKKwWuilySd08kox2XY2GM0C6saeeP/PUe1Z7wA0pZWcXHTYY\n' +
    'n6o00jjQ7WP5CsUINS6i1mHCtuEscM+D7wDECP8d2RsneS7CjY+mDr3QtDVlws3M\n' +
    'EV5TGswcouA4XzPKTNzeQyJtlYLBvw2wLIVTO4X8YDAExwZbY15371UCgYEAyFlc\n' +
    'wR/lmcDCUcbWZccAL2WAWnuQA2hr+Wd4zs0W6Qyy16RkWYOM2lgneIaVcZs30tn1\n' +
    'CyJeHZMb8zVLop922tYz8GjW685vtFibpb45H2/FkTM48M4TmsdRSMumbR3JoEJA\n' +
    'TtLn0vwEoExh1np++9oMglXZ0kXMLwb4Cx+6hc8CgYApm/at+eJ/AfZJJKffYv8G\n' +
    'DM96WF2itUQg7v5IE4Ae6PN70wcbOCTbniCwK1X37R8O0a1m5vP+vB+WKK3MZWA8\n' +
    'ZYPo1iD4+WtfLJnrm3QxUTnk3MJDrH8BrdLDW7sEwJeDUtVm64mqyKFtI53EPWJ9\n' +
    'cJfw+59zFC76zO0yn5UD+QKBgQCiw0aBduJWqKy1Nu5SvPq/hpxh5eQ3gIvHkHIq\n' +
    'v58PMcvROLJ1rlOtxtQ6LEwYgVs2pu9WXlNLf4nDadbKhPZQDpkfhGymIY3KW/oH\n' +
    'CqTpjypYLd7icuimY6r7ksbf+sUktu37m4fOdgNkHumVDus+vARRlmFhXGbnBahZ\n' +
    'kSs9LQKBgCaZxAOC/trUW+4IJMOVTImOIi/vgfI9V4b2D+Phhe1MuDPBf4sE6u5b\n' +
    'Wy7Q/Jsz8BYJ4jD1HcQvrjzix5Hnx8eWy/EIebWDFmuCokv4s3H1/rZgP/NuxBDB\n' +
    'H9q1u0YjzqiT82fkibwQNMHRy1tws7N9NXTYjKPHSk8POSfFQ872\n' +
    '-----END RSA PRIVATE KEY-----\n'
});
data.keys[keyId] = createPublicKeyDoc({
  keyId: keyId,
  publicKeyPem: identities[userName].keys.publicKey.publicKeyPem,
  userId: userName
});
keyId = '31e76c9d-0cb9-4d0a-9154-584a58fc4bab';
data.owners[userName] = createOwnerDoc({
  keyId: keyId,
  userId: userName
});

// zeta has an ed25519 keypair
userName = 'zeta';
keyId = 'd6d09ca6-253d-4db9-b0cd-05d535fc631a';
identities[userName] = {};
identities[userName].identity = helpers.createIdentity(userName);
identities[userName].meta = {
  sysResourceRole: [{
    sysRole: 'credential.user',
    generateResource: 'id'
  }]
};
identities[userName].keys = helpers.createKeyPair({
  userName: userName,
  userId: identities[userName].identity.id,
  keyId: keyId,
  publicKeyBase58: 'GycSSui454dpYRKiFdsQ5uaE8Gy3ac6dSMPcAoQsk8yq',
  privateKeyBase58:
    '3Mmk4UzTRJTEtxaKk61LxtgUxAa2Dg36jF6VogPtRiKvfpsQWKPCLesKSV182RMmvM' +
    'JKk6QErH3wgdHp8itkSSiF'
});
data.keys[keyId] = createPublicKeyDoc({
  keyId,
  publicKeyBase58: identities[userName].keys.publicKey.publicKeyBase58,
  userId: userName
});
data.owners[userName] = createOwnerDoc({keyId, userId: userName});

function createOwnerDoc(options) {
  return {

    // FIXME: proper context? is `CryptographicKey` appropriate here even
    // if the key document includes a more specific type as well?  see key
    // doc below

    '@context': constants.IDENTITY_CONTEXT_V1_URL,
    'id': 'https://' + config.server.host + '/tests/i/' + options.userId,
    'type': 'Identity',
    'publicKey': {
      'type': 'CryptographicKey',
      'owner': 'https://' + config.server.host + '/tests/i/' + options.userId,
      'label': 'Access Key 1',
      'id': 'https://' + config.server.host + '/keys/' + options.keyId
    }
  };
}

function createPublicKeyDoc({keyId, publicKeyPem, publicKeyBase58, userId}) {
  const doc = {
    '@context': constants.SECURITY_CONTEXT_V2_URL,
    owner: `https://${config.server.host}/tests/i/${userId}`,
    label: 'Access Key 1',
    id: `https://${config.server.host}/keys/${keyId}`,
    sysStatus: 'active'
  };
  if(publicKeyPem) {
    doc.type = ['CryptographicKey', 'RsaVerificationKey2018'];
    doc.publicKeyPem = publicKeyPem;
  }
  if(publicKeyBase58) {
    doc.type = ['CryptographicKey', 'Ed25519VerificationKey2018'];
    doc.publicKeyBase58 = publicKeyBase58;
  }
  return doc;
}
