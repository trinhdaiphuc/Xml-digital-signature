const crypto = require("crypto");

module.exports = {
  SHA1: {
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
  },
  SHA256: {
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
  },
  RSASHA1: {
    getSignature(signedInfo, signingKey) {
      const signer = crypto.createSign("RSA-SHA1");
      signer.update(signedInfo);
      return signer.sign(signingKey, "base64");
    },
    verifySignature(str, key, signatureValue) {
      const verifier = crypto.createVerify("RSA-SHA1");
      verifier.update(str);
      return verifier.verify(key, signatureValue, "base64");
    },
  },
  RSASHA256: {
    getSignature(signedInfo, signingKey) {
      const signer = crypto.createSign("RSA-SHA256");
      signer.update(signedInfo);
      return signer.sign(signingKey, "base64");
    },
    verifySignature(str, key, signatureValue) {
      const verifier = crypto.createVerify("RSA-SHA256");
      verifier.update(str);
      return verifier.verify(key, signatureValue, "base64");
    },
  },
};
