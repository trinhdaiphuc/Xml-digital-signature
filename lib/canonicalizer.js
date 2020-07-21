const c14n = require("./c14n-canonicalization");
const exc = require("./exclusive-canonicalization");

const canonicalizeAlgorithm = {
  "http://www.w3.org/TR/2001/REC-xml-c14n-20010315": c14n.C14nCanonicalization,
  "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments":
    c14n.C14nCanonicalizationWithComments,
  "http://www.w3.org/2001/10/xml-exc-c14n#": exc.ExclusiveCanonicalization,
  "http://www.w3.org/2001/10/xml-exc-c14n#WithComments": exc.ExclusiveCanonicalizationWithComments,
};

module.exports = {
  getCanonicalizeAlgorithm(algorithm) {
    return !algorithm || !canonicalizeAlgorithm[algorithm]
      ? c14n.C14nCanonicalization
      : canonicalizeAlgorithm[algorithm];
  },
};
