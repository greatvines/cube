var crypto = require('crypto');

var signedRequestAuth = {};

signedRequestAuth.checkSignature = function(signature, key, payload) {
  var signer = crypto.createHmac('sha256', key);
  var hmac = signer.update(payload).digest('base64');
  return signature == hmac;
}

signedRequestAuth.parseSignedRequest = function(signedRequest) {
  if (!signedRequest) {
    throw "No signed request found";
  }
  var array = signedRequest.split('.');
  if (array.length != 2) {
    throw "Incorrectly formatted signed request";
  }
  var sr = {
    signature: array[0],
    payload: array[1]
  };
  return sr;
}

signedRequestAuth.checkSignedRequest = function(signedRequest, consumerSecret, good, bad) {
  try {
    var sr = signedRequestAuth.parseSignedRequest(signedRequest);
    var signature = sr.signature;
    var payload = sr.payload;

    if (!signedRequestAuth.checkSignature(signature, consumerSecret, payload)) {
      throw "Invalid Signature";
    }
    /*
    TODO: extract specific attributes from signed request
    var jsonString = (new Buffer(payload, 'base64')).toString();
    var signedRequest = JSON.parse(jsonString);
    good(signedRequest);
    */
    good({signed: true});
  } catch(e) {
    console.log(e);
    bad(e);
  }
}

signedRequestAuth.deserializePayload = function(payload) {
  var jsonString = (new Buffer(payload, 'base64')).toString();
  var object = JSON.parse(jsonString);
  return object;
};

module.exports = signedRequestAuth;
