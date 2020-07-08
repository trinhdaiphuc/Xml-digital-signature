const Dom = require("xmldom").DOMParser;
const { SHA256, RSASHA256 } = require("./algorithm");

const validateXml = (signXml, callback) => {
  const root = new Dom().parseFromString(signXml);

  // Get xml data object
  const doc = root;
  const signatureNode = doc.documentElement.getElementsByTagName("Signature")[0];
  doc.documentElement.removeChild(signatureNode);

  // Verify reference
  const digestValueNode = signatureNode.getElementsByTagName("DigestValue")[0];
  const digestValue = digestValueNode.firstChild.data;
  const digestXmlObject = SHA256.getDigest(doc.toString());
  if (!SHA256.verifyDigestValue(digestValue, digestXmlObject)) return callback(false, null);

  // Get signature value
  const signInfoNode = signatureNode.getElementsByTagName("SignedInfo")[0];
  signInfoNode.removeAttribute("xmlns");
  const signedInfoValue = signInfoNode.toString();
  const out = signedInfoValue.replace(` xmlns="http://www.w3.org/2000/09/xmldsig#"`, "");
  const signatureValue = signatureNode.getElementsByTagName("SignatureValue")[0].firstChild.data;
  const keyValue = signatureNode.getElementsByTagName("X509Certificate")[0].firstChild.data;

  // Create public key from KeyValue object
  let pem = "-----BEGIN CERTIFICATE-----\r\n";
  for (var i = 0; i < keyValue.length; i += 64) {
    var len = keyValue.length - i;
    if (len > 64) {
      len = 64;
    }
    pem += keyValue.substr(i, len) + "\r\n";
  }
  pem += "-----END CERTIFICATE-----";

  const pub = Buffer.from(pem);
  // Verify signature
  try {
    const check = RSASHA256.verifySignature(out, pub, signatureValue);
    return callback(check, null);
  } catch (error) {
    return callback(null, error);
  }
};

module.exports = validateXml;
