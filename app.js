
/**
 * Module dependencies.
 */

var express             = require('express'),
    os                  = require('os'),
    fs                  = require('fs'),
    http                = require('http'),
    path                = require('path'),
    samlp               = require('samlp'),
    config              = require('./config.js'),
    SimpleProfileMapper = require('./simpleProfileMapper.js');


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

console.log();
console.log('loading configuration...');
console.log();
console.log('Listener Port:\n\t' + argv.port);
console.log('IdP Issuer URI:\n\t' + argv.issuer);
console.log('SP ACS URL:\n\t' + argv.acs);
console.log('SP Audience URI:\n\t' + argv.audience);
console.log('Default RelayState:\n\t' + argv.relaystate);
console.log();

// idp options
var idpOptions = {
  issuer:               argv.issuer,
  cert:                 fs.readFileSync(path.join(__dirname, 'server-cert.pem')),
  key:                  fs.readFileSync(path.join(__dirname, 'server-key.pem')),
  audience:             argv.audience,
  recipient:            argv.acs, 
  digestAlgorithm:      'sha1',      
  signatureAlgorithm:   'rsa-sha1',
  RelayState:           argv.relaystate,
  profileMapper:        SimpleProfileMapper,
  getUserFromRequest:   function(req) { return config.user; },
  getPostURL:           function (audience, authnRequestDom, req, callback) { 
                          return callback(null, argv.acs);
                        }
}

// globals
var app    = express();
var server = http.createServer(app);

// all environments
app.set('port', process.env.PORT || argv.port);
app.use(express.logger(':date> :method :url - {:referrer} => :status (:response-time ms)'));
app.use(express.urlencoded());
app.use(app.router);

// development only
if ('development' == app.get('env')) {
  app.use(express.errorHandler());
}

// register idp flow route
app.get('/', samlp.auth(idpOptions));
app.post('/', samlp.auth(idpOptions));
app.get('/idp', samlp.auth(idpOptions));
app.post('/idp', samlp.auth(idpOptions));
app.get('/metadata', samlp.metadata(idpOptions));


console.log('starting server...');
server.listen(app.get('port'), function() {
  var address  = server.address(),
      hostname = os.hostname();
      baseUrl  = address.address === '0.0.0.0' ? 
        'http://' + hostname + ':' + address.port :
        'http://localhost:' + address.port
  
  console.log('listening on port: ' + app.get('port'));
  console.log();
  console.log('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST');
  console.log('\t=> ' + baseUrl + '/idp')
  console.log('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect');
  console.log('\t=> ' + baseUrl + '/idp')
  console.log();
});
