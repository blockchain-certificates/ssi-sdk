// eslint-disable-next-line import/extensions
import { secp256k1 } from '@noble/curves/secp256k1.js'
// @ts-expect-error: implicit type import; not a ts package
import * as base58 from 'base58-universal'
// @ts-expect-error: implicit type import; not a ts package
import * as base64url from 'base64url-universal'

const compressedHexEncodedPublicKeyLength = 66

export type PrivateKeyJWK = {
  kty: string
  crv: string
  d: string
  x: string
  y: string
  kid: string
}

export type PublicKeyJWK = {
  kty: string
  crv: string
  x: string
  y: string
  kid: string
}

const ECDSA_CURVE = {
  P256: 'P-256',
  P384: 'P-384',
  P521: 'P-521',
  // compatibility with @peculiar/webcrypto
  secp256k1: 'K-256',
};

function getSecretKeySize({curve}) {
  if(curve === ECDSA_CURVE.P256 || curve === ECDSA_CURVE.secp256k1 || curve === 'secp256k1') {
    return 32;
  }
  if(curve === ECDSA_CURVE.P384) {
    return 48;
  }
  if(curve === ECDSA_CURVE.P521) {
    return 66;
  }
  throw new TypeError(`Unsupported curve "${curve}".`);
}

function toPublicKeyBytes({ jwk } = {} as any): Uint8Array {
  if (jwk?.kty !== 'EC') {
    throw new TypeError('"jwk.kty" must be "EC".');
  }
  const { crv: curve } = jwk;
  const secretKeySize = getSecretKeySize({ curve })
  // convert `x` coordinate to compressed public key
  const x = base64url.decode(jwk.x);
  const y = base64url.decode(jwk.y);
  // public key size is always secret key size + 1
  const publicKeySize = secretKeySize + 1;
  const publicKey = new Uint8Array(publicKeySize);
  // use even / odd status of `y` coordinate for compressed header
  const even = y[y.length - 1] % 2 === 0;
  publicKey[0] = even ? 2 : 3;
  // write `x` coordinate at end of multikey buffer to zero-fill it
  publicKey.set(x, publicKey.length - x.length);
  return publicKey;
}

export function toSecretKeyBytes({jwk} = {} as any): Uint8Array {
  if(jwk?.kty !== 'EC') {
    throw new TypeError('"jwk.kty" must be "EC".');
  }
  const {crv: curve} = jwk;
  const secretKeySize = getSecretKeySize({curve});
  const d = base64url.decode(jwk.d);
  const secretKey = new Uint8Array(secretKeySize);
  // write `d` at end of multikey buffer to zero-fill it
  secretKey.set(d, secretKey.length - d.length);
  return secretKey;
}

function bigIntToBytes(num, length = null) {
  let hex = num.toString(16);
  if (hex.length % 2) hex = '0' + hex;

  let bytes = Uint8Array.from(hex.match(/.{2}/g).map(b => parseInt(b, 16)));

  if (length !== null) {
    if (bytes.length > length) {
      throw new Error('BigInt too large');
    }
    const padded = new Uint8Array(length);
    padded.set(bytes, length - bytes.length); // left pad
    bytes = padded;
  }

  return bytes;
}

export const publicKeyHexFrom = {
  publicKeyBase58: (publicKeyBase58: string): string => Buffer.from(base58.decode(publicKeyBase58)).toString('hex'),
  publicKeyJWK: (jwk: PublicKeyJWK): string => Buffer.from(toPublicKeyBytes({ jwk })).toString('hex'),
  publicKeyUint8Array: (publicKeyUint8Array: Uint8Array): string => Buffer.from(publicKeyUint8Array).toString('hex'),
  privateKeyHex: (privateKeyHex: string): string =>
    Buffer.from(secp256k1.getPublicKey(new Uint8Array(Buffer.from(privateKeyHex, 'hex')))).toString('hex'),
}

export const privateKeyHexFrom = {
  privateKeyBase58: (privateKeyBase58: string): string => Buffer.from(base58.decode(privateKeyBase58)).toString('hex'),
  privateKeyJWK: (jwk: PrivateKeyJWK): string => Buffer.from(toSecretKeyBytes({ jwk })).toString('hex'),
  privateKeyUint8Array: (privateKeyUint8Array: Uint8Array): string => Buffer.from(privateKeyUint8Array).toString('hex'),
}

export const publicKeyUint8ArrayFrom = {
  publicKeyBase58: (publicKeyBase58: string): Uint8Array => base58.decode(publicKeyBase58),
  publicKeyHex: (publicKeyHex: string): Uint8Array => Uint8Array.from(Buffer.from(publicKeyHex, 'hex')),
  publicKeyJWK: (jwk: PublicKeyJWK): Uint8Array => {
    let asBuffer = Buffer.from(publicKeyHexFrom.publicKeyJWK(jwk), 'hex')
    let padding = 32 - asBuffer.length
    while (padding > 0) {
      asBuffer = Buffer.concat([Buffer.from('00', 'hex'), asBuffer])
      padding -= 1
    }
    return Uint8Array.from(asBuffer)
  },
  privateKeyUint8Array: (privateKeyUint8Array: Uint8Array): Uint8Array => secp256k1.getPublicKey(privateKeyUint8Array),
}

export const privateKeyUint8ArrayFrom = {
  privateKeyBase58: (privateKeyBase58: string): Uint8Array => base58.decode(privateKeyBase58),
  privateKeyHex: (privateKeyHex: string): Uint8Array => Uint8Array.from(Buffer.from(privateKeyHex, 'hex')),
  privateKeyJWK: (jwk: PrivateKeyJWK): Uint8Array => {
    let asBuffer = Buffer.from(privateKeyHexFrom.privateKeyJWK(jwk), 'hex')
    let padding = 32 - asBuffer.length
    while (padding > 0) {
      asBuffer = Buffer.concat([Buffer.from('00', 'hex'), asBuffer])
      padding -= 1
    }
    return Uint8Array.from(asBuffer)
  },
}

export const publicKeyJWKFrom = {
  publicKeyBase58: (publicKeybase58: string, kid: string): PublicKeyJWK =>
    publicKeyJWKFrom.publicKeyHex(Buffer.from(base58.decode(publicKeybase58)).toString('hex'), kid),
  publicKeyHex: (publicKeyHex: string, kid: string): PublicKeyJWK => {
    let point
    if (publicKeyHex.length === compressedHexEncodedPublicKeyLength) {
      const P = secp256k1.Point.fromHex(publicKeyHex)
      point = {
        x: bigIntToBytes(P.x),
        y: bigIntToBytes(P.y),
      }
    } else {
      point = {
        x: Buffer.from(publicKeyHex.slice(2, publicKeyHex.length / 2 + 1), 'hex'),
        y: Buffer.from(publicKeyHex.slice(publicKeyHex.length / 2 + 1), 'hex'),
      }
    }

    const jwk = {
      x: base64url.encode(point.x),
      y: base64url.encode(point.y),
    }

    return {
      ...jwk,
      crv: 'secp256k1',
      kty: 'EC',
      kid,
    }
  },
  publicKeyUint8Array: (publicKeyUint8Array: Uint8Array, kid: string): PublicKeyJWK =>
    publicKeyJWKFrom.publicKeyHex(Buffer.from(publicKeyUint8Array).toString('hex'), kid),
  privateKeyJWK: (privateKeyJWK: PrivateKeyJWK): PublicKeyJWK => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { d, ...publicKeyJWK } = privateKeyJWK

    return publicKeyJWK
  },
}

export const privateKeyJWKFrom = {
  privateKeyBase58: (privateKeybase58: string, kid: string): PrivateKeyJWK =>
    privateKeyJWKFrom.privateKeyHex(Buffer.from(base58.decode(privateKeybase58)).toString('hex'), kid),
  privateKeyHex: (privateKeyHex: string, kid: string): PrivateKeyJWK => {
    const priv = Buffer.from(privateKeyHex, 'hex')
    const uncompressedPub = secp256k1.getPublicKey(priv, false)

    const publicKeyJwk = publicKeyJWKFrom.publicKeyHex(Buffer.from(uncompressedPub).toString('hex'), kid)
    return {
      ...publicKeyJwk,
      d: base64url.encode(Buffer.from(priv, 'hex')),
    }
  },
  privateKeyUint8Array: (privateKeyUint8Array: Uint8Array, kid: string): PrivateKeyJWK =>
    privateKeyJWKFrom.privateKeyHex(privateKeyHexFrom.privateKeyUint8Array(privateKeyUint8Array), kid),
}
