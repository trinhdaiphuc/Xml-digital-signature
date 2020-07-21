const Dom = require("xmldom").DOMParser;
const xpath = require("xpath");
const forge = require("node-forge");

const canonicalizer = require("./canonicalizer");
const algorithm = require("./algorithm");

const derToPem = (der) => {
  const derKey = forge.util.decode64(der);
  const asnObj = forge.asn1.fromDer(derKey);
  const asn1Cert = forge.pki.certificateFromAsn1(asnObj);
  return forge.pki.certificateToPem(asn1Cert);
};

const validateXml = async (signXml) => {
  if (signXml.indexOf("?>") > -1) {
    signXml = signXml.substring(signXml.indexOf("?>") + 2);
  }

  const root = new Dom().parseFromString(signXml);

  // Get xml data object
  let dataObject = root;
  const signatureNode = dataObject.documentElement.getElementsByTagName("Signature")[0];
  const referenceNode = dataObject.documentElement.getElementsByTagName("Reference")[0];
  const canonicalizationMethod = dataObject.documentElement.getElementsByTagName("CanonicalizationMethod")[0];
  const canonicalizeAlgorithm = canonicalizationMethod.getAttribute("Algorithm")
  if (referenceNode.getAttribute("URI") !== "") {
    const referenceId = referenceNode.getAttribute("URI").replace("#", "");
    let elemXpath = `//*[@Id="${referenceId}"]`;
    dataObject = xpath.select(elemXpath, root)[0];
    if (!dataObject) {
      elemXpath = `//*[@id="${referenceId}"]`;
      dataObject = xpath.select(elemXpath, root)[0];
    }
  } else {
    dataObject.documentElement.removeChild(signatureNode);
  }

  const canon = canonicalizer.getCanonicalizeAlgorithm(canonicalizeAlgorithm);
  const canonicalizerFunction = new canon();
  let dataObjectValue = canonicalizerFunction.process(dataObject);

  if (
    dataObjectValue.lastIndexOf("<>") === 0 &&
    dataObjectValue.lastIndexOf("</>") === dataObjectValue.length - 3
  ) {
    dataObjectValue = dataObjectValue.replace("<>", "");
    dataObjectValue = dataObjectValue.replace("</>", "");
  }

  // Verify reference
  const signatureMethodNode = signatureNode.getElementsByTagName("SignatureMethod")[0];
  const signAlgorithm = signatureMethodNode.getAttribute("Algorithm");
  const signatureFunction = algorithm.getSignatureAlgorithm(signAlgorithm);

  const digestMethodNode = signatureNode.getElementsByTagName("DigestMethod")[0];
  const hashAlgorithm = digestMethodNode.getAttribute("Algorithm");
  const hashFunction = algorithm.getHashAlgorithm(hashAlgorithm);

  const digestValueNode = signatureNode.getElementsByTagName("DigestValue")[0];

  const digestValue = digestValueNode.firstChild.data;

  const digestXmlObject = hashFunction.getDigest(dataObjectValue);

  if (!hashFunction.verifyDigestValue(digestValue, digestXmlObject)) {
    console.log(
      "[INFO]:::: validateXml -> hashFunction.verifyDigestValue(digestValue, digestXmlObject)",
      hashFunction.verifyDigestValue(digestValue, digestXmlObject),
    );
    return false;
  }

  // Get signature value
  const signatureValue = signatureNode.getElementsByTagName("SignatureValue")[0].firstChild.data;
  const keyValue = signatureNode.getElementsByTagName("X509Certificate")[0].firstChild.data;
  const signedInfoNode = signatureNode.getElementsByTagName("SignedInfo")[0].firstChild.parentNode;

  // Canonlize signed info data
  const signedInfoValue = canonicalizerFunction.process(signedInfoNode);

  // Create public key from KeyValue object
  const pem = derToPem(keyValue);

  // Verify signature
  try {
    const check = signatureFunction.verifySignature(signedInfoValue, pem, signatureValue);
    return check;
  } catch (error) {
    throw error;
  }
};

module.exports = validateXml;
