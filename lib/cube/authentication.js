//
// authentication -- authenticate user identities and authorize their action
//
// Call an authenticator with the request and ok/no callbacks:
// * if authentication succeeds, a permissions record is attached to the request
//   object as `request.authorized`, and sent as the callback parameter.
// * if authentication fails, the callback is called with a short string
//   describing the reason.
//
// The authenticators include:
// * allow_all -- uniformly authenticates all requests, authorizing all to write
// * read_only -- uniformly authenticates all requests, authorizing none to write
// * mongo_cookie -- validates bcrypt'ed token in cookie with user record in db.
//
// This module does not provide any means for creating user tokens; do this in
// your front-end app.
//

var mongodb  = require("mongodb"),
    cookies  = require("cookies"),
    bcrypt   = require("bcrypt"),
    metalog  = require('./metalog')
    ;

var authentication = {};

authentication.authenticator = function(strategy, db, options){
  metalog.minor('cube_auth', { strategy: strategy });
  return authentication[strategy](db, options);
}

authentication.allow_all = function(){
  function check(request, auth_ok, auth_no) {
    metalog.event('cube_auth', { authenticator: 'allow_all', path: request.url }, 'minor');
    request.authorized = { admin: true };
    return auth_ok(request.authorized);
  };
  return { check: check };
};

authentication.signed_request = function(db, options) {
  var signedRequest = require('./signed-request');
  function check(request, auth_ok, auth_no) {
    metalog.event('cube_auth', { authenticator: 'signed_request', path: request.url, method: request.method }, 'minor');
    if (request.method === 'OPTIONS') {
      return auth_ok({ anonymous: true});
    }
    var authHeader = request.headers.authorization;
    if (!authHeader) {
      return auth_no('No Authorization header found');
    }
    if (0 !== authHeader.indexOf('SIGNED_REQUEST')) {
      return auth_no('Authorization header does not contain a signed request');
    }
    signedRequest.checkSignedRequest(authHeader.substr(15), options['consumer-secret'], auth_ok, auth_no);
  };
  return { check: check };
}

authentication.recording_signed_request = function(db, options) {
  var signedRequest = require('./signed-request');
  var signedRequestChecker = authentication.signed_request(db, options).check;
  var check = function(request, auth_ok, auth_no) {
    var userRecorder = function() {
      metalog.event('cube_auth', { authenticator: 'recording_signed_request', path: request.url, method: request.method }, 'minor');
      if (request.method === 'OPTIONS') {
        return auth_ok({ anonymous: true});
      }
      var authHeader = request.headers.authorization;
      var signedReq = signedRequest.parseSignedRequest(authHeader.substr(15));
      var payload = signedReq.payload;
      try {
        payload = signedRequest.deserializePayload(payload);
        auth_ok({
          email: payload.context.user.email,
          username: payload.context.user.userName,
          userId: payload.context.user.userId,
          orgName: payload.context.organization.name,
          orgId: payload.context.organization.organizationId,
        });
      } catch (e) {
        auth_no('Invalid signed request');
      }
    }
    signedRequestChecker(request, userRecorder, auth_no);
  };
  return { check: check };
}

authentication.email_restricted_signed_request = function(db, options) {
  var signedRequest = require('./signed-request');
  var signedRequestChecker = authentication.signed_request(db, options).check;
  var check = function(request, auth_ok, auth_no) {
    var emailChecker = function() {
      metalog.event('cube_auth', { authenticator: 'email_restricted_signed_request', path: request.url, method: request.method }, 'minor');
      if (request.method === 'OPTIONS') {
        return auth_ok({ anonymous: true});
      }
      var authHeader = request.headers.authorization;
      var signedReq = signedRequest.parseSignedRequest(authHeader.substr(15));
      var payload = signedReq.payload;
      try {
        var validEmailDomain = options['valid-email'];
        var emailRegex = new RegExp('@' + validEmailDomain + '$');
        payload = signedRequest.deserializePayload(payload);
        
        // Expose the signed request payload so that we can get at the org ID in the
        // querying methods
        request.signed = payload;
        
        if (emailRegex.test(payload.context.user.email)) {
          auth_ok({ email: payload.context.user.email });
        } else {
          auth_no('Unauthorized email address');
        }
      } catch (e) {
        auth_no('Invalid signed request');
      }
    }
    signedRequestChecker(request, emailChecker, auth_no);
  };
  return { check: check };
}

authentication.orgid_restricted_signed_request = function(db, options) {
  var signedRequestChecker = authentication.signed_request(db, options).check;
  var check = function(request, auth_ok, auth_no) {
    var orgIdChecker = function() {
      metalog.event('cube_auth', {
        authenticator: 'orgid_restricted_signed_request',
        path: request.url,
        method: request.method
      }, 'minor');

      if (request.method === 'OPTIONS') {
        return auth_ok({ anonymous: true});
      }
      
      var authHeader = request.headers.authorization;
      var signedReq = signedRequest.parseSignedRequest(authHeader.substr(15));
      var payload = signedReq.payload;
      
      try {
        payload = signedRequest.deserializePayload(payload);

        // Expose the signed request payload so that we can get at the org ID in the
        // querying methods
        request.signed = payload;
        
        // TODO @kbjr @cwarder {testOrgId} is just a placeholder name, I'm still not
        // exactly sure what needs to be done here to verify the org ID in the request
        if (testOrgId(payload.context.organization.organizationID)) {
          auth_ok({ orgId: payload.context.organization.organizationID });
        } else {
          auth_no('Unauthorized organization ID');
        }
      } catch (e) {
        auth_no('Invalid signed request');
      }
    };
    signedRequestChecker(request, orgIdChecker, auth_no);
  };
  return {check: check};
}

authentication.read_only = function(){
  function check(request, auth_ok, auth_no) {
    metalog.event('cube_auth', { authenticator: 'read_only', path: request.url }, 'minor');
    request.authorized = { admin: false };
    return auth_ok(request.authorized);
  };
  return { check: check };
};

authentication.mongo_cookie = function(db, options){
  var users;

  db.collection(options["collection"]||"users", function(error, clxn){
    if (error) throw(error);
    // TODO: check if not collection?
    users = clxn;
  });

  function check(request, auth_ok, auth_no) {
    var cookie       = (new cookies(request)).get('_cube_session'),
        token        = decodeURIComponent(cookie).split('--'), // token[0] = token uid, token[1] = token secret
        token_uid    = new Buffer(token[0] + '', 'base64').toString('utf8'),
        token_secret = new Buffer(token[1] + '', 'base64').toString('utf8');

    metalog.event('cube_auth', { is: 'hi', tu: token_uid }, 'minor');

    if (! (cookie && token && token_uid && token_secret)){
      metalog.event('cube_auth', { is: 'no', r: 'no_token_in_request' });
      auth_no('no_token_in_request');
      return;
    };

    validate_token({"tokens.uid": token_uid}, auth_ok, auth_no);

    function validate_token(query, auth_ok, auth_no){
      // Asynchronously load the requested user.
      users.findOne(query, function(error, user) {
        if((!error) && user) {
          metalog.event('cube_auth', { is: 'ok', tu: token_uid, u: user._id }, 'minor');
          var auth_info = user.tokens.filter(function(t){ return t.uid === token_uid; });

          if(auth_info.length === 1){
            bcrypt.compare(token_secret, auth_info[0].hashed_secret, function(err, res) {
              if (!err && res === true ){
                delete auth_info[0].hashed_secret;
                request.authorized = auth_info[0];
                auth_ok(request.authorized);
              } else {
                metalog.event('cube_auth', { is: 'no', r: 'bad_token', tu: token_uid, u: user });
                auth_no('bad_token');
              }
            });
          } else {
            metalog.event('cube_auth', { is: 'no', r: 'missing_token', tu: token_uid, u: user });
            auth_no('missing_token');
          }
        } else {
          metalog.event('cube_auth', { is: 'no', r: 'missing_user', tu: token_uid });
          auth_no('missing_user');
        };
      });
    };
  };
  return { check: check };
};

// base-64 encode a uid and bcrypted secret
authentication.gen_cookie = function(session_name, uid, secret){
  encoded_uid = new Buffer(uid,    'utf8').toString('base64');
  encoded_sec = new Buffer(secret, 'utf8').toString('base64');
  return (session_name+"="+encoded_uid+"--"+encoded_sec+";");
};

module.exports = authentication;
