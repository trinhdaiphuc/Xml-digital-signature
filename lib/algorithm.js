const crypto = require("crypto");

const SHA1 = {
  getDigest(xmlData) {
    const shasum = crypto.createHash("sha1");
    shasum.update(xmlData, "utf8");
    return shasum.digest("base64");
  },
  verifyDigestValue(digest, expectedDigest) {
    const buffer = Buffer.from(digest, "base64");
    const expectedBuffer = Buffer.from(expectedDigest, "base64");
    return buffer.equals(expectedBuffer);
  },
  getName() {
    return "http://www.w3.org/2000/09/xmldsig#sha1";
  },
};

const SHA256 = {
  getDigest(xmlData) {
    const shasum = crypto.createHash("sha256");
    shasum.update(xmlData, "utf8");
    return shasum.digest("base64");
  },
  verifyDigestValue(digest, expectedDigest) {
    const buffer = Buffer.from(digest, "base64");
    const expectedBuffer = Buffer.from(expectedDigest, "base64");
    return buffer.equals(expectedBuffer);
  },
  getName() {
    return "http://www.w3.org/2001/04/xmlenc#sha256";
  },
};

const RSASHA1 = {
  getSignature(signedInfo, signingKey) {
    const signer = crypto.createSign("sha1");
    signer.update(signedInfo);
    return signer.sign(signingKey, "base64");
  },
  verifySignature(str, key, signatureValue) {
    const verifier = crypto.createVerify("sha1");
    verifier.update(str);
    return verifier.verify(key, signatureValue, "base64");
  },
  getName() {
    return "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
  },
};

const RSASHA256 = {
  getSignature(signedInfo, signingKey) {
    const signer = crypto.createSign("sha256");
    signer.update(signedInfo);
    return signer.sign(signingKey, "base64");
  },
  verifySignature(str, key, signatureValue) {
    const verifier = crypto.createVerify("sha256");
    verifier.update(str);
    return verifier.verify(key, signatureValue, "base64");
  },
  getName() {
    return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  },
};

const HashAlgorithm = {
  "http://www.w3.org/2000/09/xmldsig#sha1": SHA1,
  "http://www.w3.org/2001/04/xmlenc#sha256": SHA256,
};

const SignatureAlgorithm = {
  "http://www.w3.org/2000/09/xmldsig#rsa-sha1": RSASHA1,
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": RSASHA256,
};

module.exports = {
  getHashAlgorithm(algorithm) {
    return !algorithm || !HashAlgorithm[algorithm] ? SHA1 : HashAlgorithm[algorithm];
  },
  getSignatureAlgorithm(algorithm) {
    return !algorithm || !SignatureAlgorithm[algorithm] ? RSASHA1 : SignatureAlgorithm[algorithm];
  },
};
