
// ---------------------
// Generate WSSE authentication header in JavaScript
//
// inspired by https://github.com/Gerfaut/ember-simple-wsse-auth
// https://github.com/brix/crypto-js
//	<script type="text/javascript" charset="utf-8" src="js/cryptojs/core-min.js"></script>
//	<script type="text/javascript" charset="utf-8" src="js/cryptojs/x64-core-min.js"></script>
//	<script type="text/javascript" charset="utf-8" src="js/cryptojs/lib-typedarrays-min.js"></script>
//	<script type="text/javascript" charset="utf-8" src="js/cryptojs/enc-base64-min.js"></script>
//	<script type="text/javascript" charset="utf-8" src="js/cryptojs/sha1-min.js"></script>
//	<script type="text/javascript" charset="utf-8" src="js/cryptojs/sha512-min.js"></script>
//	<script type="text/javascript" charset="utf-8" src="js/app.auth.wsse.js"></script>
//	<script type="text/javascript" charset="utf-8" src="js/app.auth.js"></script>
// ---------------------
wsseAuth = {};
wsseAuth.passwordEncodingIterations = 5000;
wsseAuth.passwordEncodingAsBase64 = true;

wsseAuth.buildXWsseHeader = function(username, passwordEncoded) {
    var nonce = wsseAuth.generateNonce();
    var createdDate = wsseAuth.generateCreatedDate();
    var passwordDigest = wsseAuth.generatePasswordDigest(nonce, createdDate, passwordEncoded);
    return 'UsernameToken Username="' + username + '", PasswordDigest="' + passwordDigest + '", Nonce="' + nonce + '", Created="' + createdDate + '"';
};
  
wsseAuth.generateNonce = function() {
    var nonce = Math.random().toString(36).substring(2);
    return CryptoJS.enc.Utf8.parse(nonce).toString(CryptoJS.enc.Base64);
};

wsseAuth.generatePasswordDigest = function(nonce, createdDate, passwordEncoded) {
    var nonce_64 = CryptoJS.enc.Base64.parse(nonce);
    var _sha1 = CryptoJS.SHA1(nonce_64.concat(CryptoJS.enc.Utf8.parse(createdDate).concat(CryptoJS.enc.Utf8.parse(passwordEncoded))));
    var result = _sha1.toString(CryptoJS.enc.Base64);
    return result;
};

wsseAuth.encodePassword = function(password, salt) {
    var salted = password + '{' + salt + '}';
    var passwordEncoded = CryptoJS.SHA512(salted);
    for(var i = 1; i < wsseAuth.passwordEncodingIterations; i++) { //TODO use webworker
		passwordEncoded = CryptoJS.SHA512(passwordEncoded.concat(CryptoJS.enc.Utf8.parse(salted)));
    }
    return wsseAuth.passwordEncodingAsBase64 ? passwordEncoded.toString(CryptoJS.enc.Base64) : passwordEncoded;
};

wsseAuth.generateCreatedDate = function() {
    return new Date().toISOString();
};

wsseAuth.generateHeader = function(wsseToken) {
	$.ajaxPrefilter(function(options, originalOptions, jqXHR) {
		if (!jqXHR.crossDomain) {
		  jqXHR.setRequestHeader('Authorization', 'Authorization profile="UsernameToken"');
		  jqXHR.setRequestHeader('X-WSSE', wsseToken);
		}
	});
};