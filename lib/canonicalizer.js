// Use package xml-c14n
const xmldom = require("xmldom");
const c14n = require("xml-c14n")();

module.exports = async (xmlData, canonicalizationAlgorithm) =>
  new Promise((resolve, reject) => {
    const document = new xmldom.DOMParser().parseFromString(xmlData);
    const canonicaliser = c14n.createCanonicaliser(canonicalizationAlgorithm);
    canonicaliser.canonicalise(document.documentElement, (err, res) => {
      if (err) {
        return reject(err.stack);
      }
      resolve(res);
    });
  });
