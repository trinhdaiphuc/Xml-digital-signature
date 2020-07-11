const Dom = require("xmldom").DOMParser;
const xpath = require("xpath");
const eol = require("os").EOL;
const algorithm = require("./algorithm");

const getDataValueWithId = (xmlData, nodeName, id) => {
  const openElement = `<${nodeName} Id="${id}">`;
  const closeElement = `</${nodeName}>`;
  return xmlData.substr(
    xmlData.lastIndexOf(openElement),
    xmlData.lastIndexOf(closeElement) - xmlData.lastIndexOf(openElement) + closeElement.length,
  );
};

const getDataValueWithoutId = (xmlData) => {};

const HashAlgorithm = {
  "http://www.w3.org/2000/09/xmldsig#sha1": algorithm.SHA1,
  "http://www.w3.org/2001/04/xmlenc#sha256": algorithm.SHA256,
};

const SignatureAlgorithm = {
  "http://www.w3.org/2000/09/xmldsig#rsa-sha1": algorithm.RSASHA1,
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": algorithm.RSASHA256,
};

const canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";

const validateXml = async (signXml) => {
  const root = new Dom().parseFromString(signXml);

  // Get xml data object
  let dataObject = root;
  let dataObjectValue = "";
  const signatureNode = dataObject.documentElement.getElementsByTagName("Signature")[0];
  const referenceNode = dataObject.documentElement.getElementsByTagName("Reference")[0];
  if (referenceNode.getAttribute("URI") != "") {
    const referenceId = referenceNode.getAttribute("URI").replace("#", "");
    const elemXpath = `//*[@Id="${referenceId}"]`;
    dataObject = xpath.select(elemXpath, dataObject)[0];
    dataObjectValue = getDataValueWithId(signXml, dataObject.nodeName, referenceId);
    if (!dataObjectValue) return false;
  } else {
    dataObject.documentElement.removeChild(signatureNode);
    dataObjectValue = dataObject.toString();
  }

  // Verify reference
  const signatureMethodNode = signatureNode.getElementsByTagName("SignatureMethod")[0];
  const signAlgorithm = signatureMethodNode.getAttribute("Algorithm");
  const signatureFunction = SignatureAlgorithm[signAlgorithm];

  const digestMethodNode = signatureNode.getElementsByTagName("DigestMethod")[0];
  const hashAlgorithm = digestMethodNode.getAttribute("Algorithm");
  const hashFunction = HashAlgorithm[hashAlgorithm];

  const digestValueNode = signatureNode.getElementsByTagName("DigestValue")[0];

  const digestValue = digestValueNode.firstChild.data;

  const digestXmlObject = hashFunction.getDigest(dataObjectValue);

  if (!hashFunction.verifyDigestValue(digestValue, digestXmlObject)) return false;

  // Get signature value
  const signatureValue = signatureNode.getElementsByTagName("SignatureValue")[0].firstChild.data;
  const keyValue = signatureNode.getElementsByTagName("X509Certificate")[0].firstChild.data;
  const signedInfoValue = signXml.substr(
    signXml.lastIndexOf("<SignedInfo>"),
    signXml.lastIndexOf("</SignedInfo>") -
      signXml.lastIndexOf("<SignedInfo>") +
      "</SignedInfo>".length,
  );

  if (!signedInfoValue) return false;

  // Create public key from KeyValue object
  let pem = "-----BEGIN CERTIFICATE-----" + eol;
  for (let i = 0; i < keyValue.length; i += 64) {
    let len = keyValue.length - i;
    if (len > 64) {
      len = 64;
    }
    pem += keyValue.substr(i, len) + eol;
  }
  pem += "-----END CERTIFICATE-----" + eol;

  const pub = Buffer.from(pem);

  // Verify signature
  try {
    const check = signatureFunction.verifySignature(signedInfoValue, pub, signatureValue);
    return check;
  } catch (error) {
    throw error;
  }
};

module.exports = validateXml;
