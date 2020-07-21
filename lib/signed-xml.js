const Dom = require("xmldom").DOMParser;
const eol = require("os").EOL;

const algorithm = require("./algorithm");
const canonicalizer = require("./canonicalizer");
const transformEnvoloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

const createReference = (digestValue, algorithm) => {
  let res = "<Reference>";
  res += "<Transforms>";
  res += `<Transform Algorithm="${transformEnvoloped}"/>`;
  res += "</Transforms>";
  res += `<DigestMethod Algorithm="${algorithm}"/><DigestValue>${digestValue}</DigestValue>`;
  res += "</Reference>";
  return res;
};

const createSignedInfo = (referenceValue, canonicalizationAlgorithm, signatureAlgorithm) => {
  let res = "<SignedInfo>";
  res += `<CanonicalizationMethod Algorithm="${canonicalizationAlgorithm}"/><SignatureMethod Algorithm="${signatureAlgorithm}"/>`;
  res += referenceValue;
  res += "</SignedInfo>";
  return res;
};

const createSignedInfoDom = (canonicalizerFunction, signedInfoValue) => {
  signedInfoValue = `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">${signedInfoValue}</Signature>`
  const xmlData = new Dom().parseFromString(signedInfoValue);
  // xmlData.documentElement.setAttribute("xmlns", "http://www.w3.org/2000/09/xmldsig#");
  const signInfo = xmlData.getElementsByTagName("SignedInfo")[0].firstChild.parentNode
  const res = canonicalizerFunction.process(signInfo);
  return res;
};

const createSignature = (signatureValue, signedInfo) => {
  let res = `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">`;
  res += signedInfo;
  res += `<SignatureValue>${signatureValue}</SignatureValue>`;
  res += "</Signature>";
  return res;
};

const createKeyInfo = (publicKey) => {
  let res = "<KeyInfo>";
  res += "<X509Data>";
  res += `<X509Certificate>${publicKey}</X509Certificate>`;
  res += "</X509Data>";
  res += "</KeyInfo>";
  return res;
};

const insertSignatureToXmlData = (xmlData, signatureValue, keyInfo) => {
  const xmlDom = new Dom().parseFromString(xmlData);
  const signatureDom = new Dom().parseFromString(signatureValue);
  const keyInfoDom = new Dom().parseFromString(keyInfo);
  signatureDom.documentElement.insertBefore(keyInfoDom);
  xmlDom.documentElement.insertBefore(signatureDom);
  return xmlDom.toString();
};

// Signature Generation
const signXml = async (input, privateKey, publicKey, hashAlgorithm, signatureAlgorithm, canonicalizeAlgorithm) => {
  input = input.toString();
  privateKey = privateKey.toString();
  publicKey = publicKey.toString();
  const canon = canonicalizer.getCanonicalizeAlgorithm(canonicalizeAlgorithm);
  const canonicalizerFunction = new canon();

  const root = new Dom().parseFromString(input);

  // Canonlize data
  let xmlData = canonicalizerFunction.process(root);
  if (xmlData.lastIndexOf("<>") === 0 && xmlData.lastIndexOf("</>") === xmlData.length - 3) {
    xmlData = xmlData.replace("<>", "");
    xmlData = xmlData.replace("</>", "");
  }

  // Get data of public key
  publicKey.toString();
  const dataArray = publicKey.toString().split(eol);
  let datapublickey = "";

  for (let i = 1; i < dataArray.length - 1; i++) {
    if (dataArray[i] === "-----END CERTIFICATE-----") {
      break;
    }
    datapublickey += dataArray[i];
  }

  const hashFunction = algorithm.getHashAlgorithm(hashAlgorithm);
  const signatureFunction = algorithm.getSignatureAlgorithm(signatureAlgorithm);

  // Digest xml data object
  const digestValue = hashFunction.getDigest(xmlData);

  // Create Reference object
  const reference = createReference(digestValue, hashFunction.getName());

  // Create SignedInfo object
  const signedInfo = createSignedInfo(
    reference,
    canonicalizerFunction.getAlgorithmName(),
    signatureFunction.getName(),
  );
  const signedInfoValue = createSignedInfoDom(canonicalizerFunction, signedInfo);

  // Sign the SignedInfo object
  const signatureValue = signatureFunction.getSignature(signedInfoValue, privateKey);

  // Create Signature object
  const signature = createSignature(signatureValue, signedInfo);

  // Add key infomation
  const keyInfo = createKeyInfo(datapublickey);

  const output = insertSignatureToXmlData(xmlData, signature, keyInfo);

  return output;
};

module.exports = signXml;
