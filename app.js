
/**
 * Module dependencies.
 */

var express    			= require('express');
    fs         			= require('fs'),
    http       			= require('http'),
    path       			= require('path'),
    samlp      			= require('samlp'),
    config              = require('./config.js'),
    SimpleProfileMapper = require('./simpleProfileMapper.js');

// globals
var app = express();

var argv = require('yargs')
    .usage('Simple IdP\nUsage: $0')
    .example('$0 --acs http://acme.okta.com/auth/saml20/exampleidp --aud https://www.okta.com/saml2/service-provider/spf5aFRRXFGIMAYXQPNV', 
    		'\n\nStart IdP web server minting SAML assertions for service provider ACS URL and audience')
    .default({ p: 7000, iss: 'urn:example:idp'})
    .alias('p', 'port')
    .describe('port', 'Web server listener port')
    .alias('iss', 'issuer')
    .describe('issuer', 'IdP Issuer URI')
    .alias('url', 'acs')
    .describe('acs', 'SP Assertion Consumer URL')
    .alias('aud', 'audience')
    .describe('audience', 'SAML SP Audience')
    .alias('rs', 'relaystate')
    .describe('relaystate', 'Default SAML RelayState for AuthnResponse')
    .demand('aud', 'acs')
    .argv
;


// all environments
app.set('port', process.env.PORT || argv.port);
app.use(express.logger('dev'));;
app.use(express.urlencoded());
app.use(app.router);

// development only
if ('development' == app.get('env')) {
  app.use(express.errorHandler());
}

// register idp flow route
app.get('/idp', samlp.auth({
  issuer:               argv.issuer,
  cert:                 fs.readFileSync(path.join(__dirname, 'server-cert.pem')),
  key:                  fs.readFileSync(path.join(__dirname, 'server-key.pem')),
  audience:             argv.audience,
  recipient:            argv.acs, 
  digestAlgorithm:      'sha1',      
  signatureAlgorithm:   'rsa-sha1',
  RelayState:           argv.relayState,
  profileMapper:        SimpleProfileMapper,
  getUserFromRequest:   function(req) { return config.user; },
  getPostURL: function (audience, authnRequestDom, req, callback) { 
                return callback(null, argv.acs);
              }
}));


http.createServer(app).listen(app.get('port'), function(){
  console.log('IdP server listening on port: ' + app.get('port'));
});
