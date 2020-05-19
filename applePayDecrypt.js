import * as cryptoNative from 'crypto';
import fs from 'fs';
import path from 'path';
import ECKey from 'ec-key';
import x509 from '@fidm/x509';
import asn1js from 'asn1js';
import pkijs from 'pkijs'
import Crypto from 'node-webcrypto-ossl';

const __dirname = path.resolve();
const crypto = new Crypto.Crypto()
const TOKEN_EXPIRE_WINDOW = Infinity; // should be set to serveral minute per apple
pkijs.setEngine(
  'newEngine',
  crypto,
  new pkijs.CryptoEngine({ name: '', crypto, subtle: crypto.subtle })
);

const LEAF_CERTIFICATE_OID = '1.2.840.113635.100.6.29';
const INTERMEDIATE_CA_OID = '1.2.840.113635.100.6.2.14';
const SIGNINGTIME_OID = '1.2.840.113549.1.9.5';
const MERCHANT_ID_FIELD_OID = '1.2.840.113635.100.6.32';

const AppleRootCABuffer = fs.readFileSync(
  path.join(__dirname, './AppleRootCA-G3.cer')
);
const AppleRootCAASN1 = asn1js.fromBER(new Uint8Array(AppleRootCABuffer).buffer);
const AppleRootCA = new pkijs.Certificate({ schema: AppleRootCAASN1.result });

/**
 * Ensure that the certificates contain the correct custom OIDs
 * @param  {} certificates
 */
function checkCertificates(certificates) {
  if (certificates.length !== 2) {
    throw new Error(
      `Signature certificates number error: expected 2 but got ${certificates.length}`
    );
  }
  if (
    !certificates[0].extensions.find(x => x.extnID === LEAF_CERTIFICATE_OID)
  ) {
    throw new Error(
      `Leaf certificate doesn't have extension: ${LEAF_CERTIFICATE_OID}`
    );
  }
  if (!certificates[1].extensions.find(x => x.extnID === INTERMEDIATE_CA_OID)) {
    throw new Error(
      `Intermediate certificate doesn't have extension: ${INTERMEDIATE_CA_OID}`
    );
  }
}

/**
 * Validate the token’s signature
 * @param  {} cmsSignedData CMS signed data structure
 * @param  {} rootCA apple's root CA
 * @param  {} signedData the data buffer consist of ephemeralPublicKey, data, and transactionId
 */
function validateSignature(cmsSignedData, rootCA, signedData) {
  return cmsSignedData.verify({
    signer: 0, // should only contain 1 signer, verify with it
    trustedCerts: [rootCA],
    data: signedData,
    checkChain: true, // check x509 chain of trust
    extendedMode: true, // enable to show signature validation result
  });
}

/**
 * Inspect the CMS signing time of the signature
 * @param  {} signerInfo signer information from cmsSignedData
 */
function checkSigningTime(signerInfo) {
  const signerInfoAttrs = signerInfo.signedAttrs.attributes;
  const attr = signerInfoAttrs.find(x => x.type === SIGNINGTIME_OID);
  const signedTime = new Date(attr.values[0].toDate());
  const now = new Date();
  if (now - signedTime > TOKEN_EXPIRE_WINDOW) {
    throw new Error('Signature has expired');
  }
}

/**
 * Verify the signature of payment token
 * @param  {Object} token apple pay payment token object
 */
async function verifySignature(token) {
  // refer to Apple developer site of Payment Token Format
  const p1 = Buffer.from(token.header.ephemeralPublicKey, 'base64');
  const p2 = Buffer.from(token.data, 'base64');
  const p3 = Buffer.from(token.header.transactionId, 'hex');
  const signedData = Buffer.concat([p1, p2, p3]);

  const cmsSignedBuffer = Buffer.from(token.signature, 'base64');
  const cmsSignedASN1 = asn1js.fromBER(new Uint8Array(cmsSignedBuffer).buffer);
  const cmsContentSimpl = new pkijs.ContentInfo({
    schema: cmsSignedASN1.result,
  });
  const cmsSignedData = new pkijs.SignedData({
    schema: cmsContentSimpl.content,
  });
  const signerInfo = cmsSignedData.signerInfos[0];

  // 1.a Ensure that the certificates contain the correct custom OIDs: 1.2.840.113635.100.6.29
  // for the leaf certificate and 1.2.840.113635.100.6.2.14 for the intermediate CA
  checkCertificates(cmsSignedData.certificates);

  // 1.b Ensure that the root CA is the Apple Root CA - G3
  // root CA downloaded from Apple web site so we're good

  // 1.c Ensure that there is a valid X.509 chain of trust from the signature to the root CA
  // 1.d Validate the token’s signature
  // PKI.js can check chain of trust and verify on one shot, so 1.c and 1.d can be done together
  const ret = await validateSignature(cmsSignedData, AppleRootCA, signedData);
  if (!ret.signatureVerified) {
    throw new Error('CMS signed data verification failed');
  }
  // 1.e Inspect the CMS signing time of the signature
  checkSigningTime(signerInfo);
}

/**
 * Ensure we are using the right key pair
 * @param  {String} publicKeyHash public hash string from payment token
 */
function checkPublicKeyHash(publicKeyHash, publicCert) {
  const info = x509.Certificate.fromPEM(publicCert);
  const subjectPublicKeyInfo = info.publicKeyRaw;
  const hash = cryptoNative
    .createHash('sha256')
    .update(subjectPublicKeyInfo)
    .digest('base64');
  return hash === publicKeyHash;
}

/**
 * Use the merchant private key and the ephemeral public key, to generate the shared secret using
 * Elliptic Curve Diffie-Hellman
 * @param  {String} ephemeralPublicKey ephemeralPublicKey from payment token
 */
function sharedSecretFunc(ephemeralPublicKey, privateKey) {
  const prv = new ECKey(privateKey, 'pem'); // Create a new ECkey instance from PEM formatted string
  const publicEc = new ECKey(ephemeralPublicKey, 'spki'); // Create a new ECKey instance from a base-64 spki string
  return prv.computeSecret(publicEc).toString('hex'); // Compute secret using private key for provided ephemeral public key
}

/**
 * Extract the merchant identification from public key certificate
 */
function merchantIdFunc(publicCert) {
  try {
    const info = x509.Certificate.fromPEM(publicCert);
    const picked = info.extensions.find(x => x.oid === MERCHANT_ID_FIELD_OID);
    return picked.value.toString().substring(2);
  } catch (err) {
    throw new Error(`Unable to extract merchant ID from certificate: ${err}`);
  }
}

/**
 * Derive the symmetric key
 * @param  {String} merchantId merchantId
 * @param  {String} sharedSecret sharedSecret
 */
function symmetricKeyFunc(merchantId, sharedSecret) {
  const KDF_ALGORITHM = '\x0did-aes256-GCM'; // The byte (0x0D) followed by the ASCII string "id-aes256-GCM". The first byte of this value is an unsigned integer that indicates the string’s length in bytes; the remaining bytes are a constiable-length string.
  const KDF_PARTY_V = Buffer.from(merchantId, 'hex').toString('binary'); // The SHA-256 hash of your merchant ID string literal; 32 bytes in size.
  const KDF_PARTY_U = 'Apple'; // The ASCII string "Apple". This value is a fixed-length string.
  const KDF_INFO = KDF_ALGORITHM + KDF_PARTY_U + KDF_PARTY_V;

  const hash = cryptoNative.createHash('sha256');
  hash.update(Buffer.from('000000', 'hex'));
  hash.update(Buffer.from('01', 'hex'));
  hash.update(Buffer.from(sharedSecret, 'hex'));
  hash.update(KDF_INFO, 'binary');

  return hash.digest('hex');
}

/**
 * Restore the symmetric key
 * @param  {String} ephemeralPublicKey the ephemeralPublicKey from payment token
 */
function restoreSymmetricKey(ephemeralPublicKey, publicCert, privateKey) {
  // 3.a Use the merchant private key and the ephemeral public key, to generate the shared secret
  const sharedSecret = sharedSecretFunc(ephemeralPublicKey, privateKey);

  // 3.b Use the merchant identifier of the public key certificate and the shared secret, to derive the symmetric key
  const merchantId = merchantIdFunc(publicCert);

  return symmetricKeyFunc(merchantId, sharedSecret);
}

/**
 * Use the symmetric key to decrypt the value of the data key
 * @param  {String} symmetricKey symmetric key restored from previous steps
 * @param  {String} data encrypted data from payment token
 */
function decryptCiphertextFunc(symmetricKey, data) {
  const buf = Buffer.from(data, 'base64');
  const SYMMETRIC_KEY = Buffer.from(symmetricKey, 'hex');
  const IV = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // Initialization vector of 16 null bytes
  const CIPHERTEXT = buf.slice(0, -16);
  const decipher = cryptoNative.createDecipheriv(
    'aes-256-gcm',
    SYMMETRIC_KEY,
    IV
  ); // Creates and returns a Decipher object that uses the given algorithm and password (key)
  const tag = buf.slice(-16, buf.length);

  decipher.setAuthTag(tag);
  let decrypted = decipher.update(CIPHERTEXT);
  decrypted += decipher.final();
  return decrypted;
}

class ApplePayPaymentToken {
  constructor(token) {
    this.token = token;
  }

  async decrypt(publicCert, privateKey) {
    // 1. Verify the signature
    try {
      await verifySignature(this.token);
    } catch (err) {
      throw new Error(`Signature validation failed: ${err.message}`);
    }

    // 2. Use the value of the publicKeyHash key to determine which merchant public key was used
    if (!checkPublicKeyHash(this.token.header.publicKeyHash, publicCert)) {
      throw new Error('Public key hash does not match');
    }

    // 3. restore the symmetric key
    let symmetricKey = '';
    try {
      symmetricKey = restoreSymmetricKey(this.token.header.ephemeralPublicKey, publicCert, privateKey);
    } catch (err) {
      throw new Error(`Restore symmetric key failed: ${err.message}`);
    }

    try {
      // 4. Use the symmetric key to decrypt the value of the data key
      const decrypted = decryptCiphertextFunc(symmetricKey, this.token.data);

      return JSON.parse(decrypted);
    } catch (err) {
      throw new Error(`Decrypt cipher data failed: ${err.message}`);
    }
  }
}

export default ApplePayPaymentToken;
