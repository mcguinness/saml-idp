
/**
 * Module dependencies.
 */

var express             = require('express'),
    os                  = require('os'),
    fs                  = require('fs'),
    http                = require('http'),
    path                = require('path'),
    hbsEngine           = require('express3-handlebars'),
    logger              = require('morgan'),
    favicon             = require('static-favicon'),
    cookieParser        = require('cookie-parser'),
    bodyParser          = require('body-parser'),
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
  getUserFromRequest:   function(req) { return req.user; },
  getPostURL:           function (audience, authnRequestDom, req, callback) { 
                          return callback(null, argv.acs);
                        }
}
// idp handler
var idpHandler = samlp.auth(idpOptions);

// globals
var app    = express();
var server = http.createServer(app);

// environment
app.set('port', process.env.PORT || argv.port);
app.set('views', path.join(__dirname, 'views'));
// view engine
app.engine('hbs', hbsEngine({extname:'hbs', defaultLayout:'main.hbs'}));
app.set('view engine', 'hbs');
// middleware
app.use(favicon());
app.use(logger(':date> :method :url - {:referrer} => :status (:response-time ms)'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));


// add default user to request
app.use(function(req,res,next){
    req.user = config.user;
    next();
});


// add routes
app.get(['/', '/idp'], function(req, res) {
    var user = req.user;
    res.render('user', {
        "user" : user
    });
});

app.post(['/', '/idp'], function(req, res) {
  if (req.body.SAMLRequest) {
    var user = req.user;
    res.render('user', {
        "user" : user
    });
  } else {
    req.user.id = req.body.login;
    req.user.firstName = req.body.firstName;
    req.user.lastName = req.body.lastName;
    req.user.email = req.body.email;
    idpHandler(req, res);
  }
});

app.get('/metadata', idpHandler);


// catch 404 and forward to error handler
app.use(function(req, res, next) {
    var err = new Error('Not Found');
    err.status = 404;
    next(err);
});

// development error handler
app.use(function(err, req, res, next) {
  res.status(err.status || 500);
  res.render('error', {
      message: err.message,
      error: err
  });
});


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
