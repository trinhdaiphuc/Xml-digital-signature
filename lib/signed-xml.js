const Dom = require("xmldom").DOMParser;
const eol = require("os").EOL;

const canonicalizer = require("./canonicalizer");
const { SHA256, RSASHA256 } = require("./algorithm");
const digestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";
const signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
const transformEnvoloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

const createReference = (digestValue) => {
  let res = "<Reference>";
  res += "<Transforms>";
  res += `<Transform Algorithm="${transformEnvoloped}"/>`;
  res += `<Transform Algorithm="${canonicalizationAlgorithm}"/>`;
  res += "</Transforms>";
  res += `<DigestMethod Algorithm="${digestAlgorithm}"/><DigestValue>${digestValue}</DigestValue>`;
  res += "</Reference>";
  return res;
};

const createSignedInfo = (referenceValue) => {
  let res = "<SignedInfo>";
  res += `<CanonicalizationMethod Algorithm="${canonicalizationAlgorithm}"/><SignatureMethod Algorithm="${signatureAlgorithm}"/>`;
  res += referenceValue;
  res += "</SignedInfo>";
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
const signXml = async (input, privateKey, publicKey) => {
  input = input.toString();
  privateKey = privateKey.toString();
  publicKey = publicKey.toString();
  // Canonlize data
  const xmlData = await canonicalizer(input, canonicalizationAlgorithm).catch((e) => {
    console.error("[ERROR]:::: e", e);
  });

  // Get data of public key
  publicKey.toString();
  const dataArray = publicKey.toString().split(eol);
  console.log("[INFO]:::: signXml -> dataArray", dataArray);
  let datapublickey = "";

  for (let i = 1; i < dataArray.length - 1; i++) {
    if (dataArray[i]=="-----END CERTIFICATE-----") {
      break;
    }
    datapublickey += dataArray[i];
  }

  // Digest xml data object
  const digestValue = SHA256.getDigest(xmlData);

  // Create Reference object
  const reference = createReference(digestValue);

  // Create SignedInfo object
  const signedInfo = createSignedInfo(reference);

  // Sign the SignedInfo object
  const signatureValue = RSASHA256.getSignature(signedInfo, privateKey);

  // Create Signature object
  const signature = createSignature(signatureValue, signedInfo);

  // Add key infomation
  const keyInfo = createKeyInfo(datapublickey);

  const output = insertSignatureToXmlData(xmlData, signature, keyInfo);

  return output;
};

module.exports = signXml;
