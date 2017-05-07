
/**
 * Module dependencies.
 */

var express             = require('express'),
    os                  = require('os'),
    fs                  = require('fs'),
    http                = require('http'),
    https               = require('https'),
    path                = require('path'),
    extend              = require('extend'),
    hbs                 = require('hbs'),
    logger              = require('morgan'),
    cookieParser        = require('cookie-parser'),
    bodyParser          = require('body-parser'),
    samlp               = require('samlp'),
    yargs               = require('yargs'),
    config              = require('./config.js'),
    SimpleProfileMapper = require('./lib/simpleProfileMapper.js');

/**
 * Globals
 */

var app                 = express(),
    blocks              = {},
    httpServer;


/**
 * Arguments
 */

console.log();
console.log('loading configuration...');
var argv = yargs
  .usage('\nSimple IdP for SAML 2.0 WebSSO Profile\n\n' +
      'Launches Web Server that mints SAML assertions for a Service Provider (SP)\n\n' +
      'Usage:\n\t$0 -acs {url} -aud {uri}', {
    port: {
      description: 'Web Server Listener Port',
      required: true,
      alias: 'p',
      default: 7000
    },
    cert: {
      description: 'IdP Signature PublicKey Certificate',
      required: true,
      default: './idp-public-cert.pem'
    },
    key: {
      description: 'IdP Signature PrivateKey Certificate',
      required: true,
      default: './idp-private-key.pem'
    },
    issuer: {
      description: 'IdP Issuer URI',
      required: true,
      alias: 'iss',
      default: 'urn:example:idp'
    },
    acsUrl: {
      description: 'SP Assertion Consumer URL',
      required: true,
      alias: 'acs'
    },
    audience: {
      description: 'SP Audience URI',
      required: true,
      alias: 'aud'
    },
    relayState: {
      description: 'Default SAML RelayState for SAMLResponse',
      required: false,
      alias: 'rs'
    },
    disableRequestAcsUrl: {
      description: 'Disables ability for SP AuthnRequest to specify Assertion Consumer URL',
      required: false,
      boolean: true,
      alias: 'static',
      default: false
    },
    encryptionCert: {
      description: 'SP Certificate (pem) for Assertion Encryption',
      required: false,
      string: true,
      alias: 'encCert'
    },
    encryptionPublicKey: {
      description: 'SP RSA Public Key (pem) for Assertion Encryption ' +
      '(e.g. openssl x509 -pubkey -noout -in sp-cert.pem)',
      required: false,
      string: true,
      alias: 'encKey'
    },
    httpsPrivateKey: {
      description: 'Web Server TLS/SSL Private Key (pem)',
      required: false,
      string: true,
    },
    httpsCert: {
      description: 'Web Server TLS/SSL Certificate (pem)',
      required: false,
      string: true,
    },
    https: {
      description: 'Enables HTTPS Listener (requires httpsPrivateKey and httpsCert)',
      required: true,
      boolean: true,
      default: false
    },
    signResponse: {
      description: 'Enables signing of responses',
      required: false,
      boolean: true,
      default: false,
      alias: 'signResponse'
    }
  })
  .example('\t$0 --acs http://acme.okta.com/auth/saml20/exampleidp --aud https://www.okta.com/saml2/service-provider/spf5aFRRXFGIMAYXQPNV', '')
  .check(function(argv, aliases) {
    if (!fs.existsSync(argv.cert)) {
      return 'IdP Signature PublicKey Certificate "' + argv.cert + '" is not a valid file path.\n' +
        "Please generate a key-pair for the IdP using the following openssl command:\n" +
        "\topenssl req -x509 -new -newkey rsa:2048 -nodes -subj '/C=US/ST=California/L=San Francisco/O=JankyCo/CN=Test Identity Provider' -keyout idp-private-key.pem -out idp-public-cert.pem -days 7300"
    }

    if (!fs.existsSync(argv.key)) {
      return 'IdP Signature PrivateKey Certificate "' + argv.key + '" is not a valid file path.\n' +
        "Please generate a key-pair for the IdP using the following openssl command:\n" +
        "\topenssl req -x509 -new -newkey rsa:2048 -nodes -subj '/C=US/ST=California/L=San Francisco/O=JankyCo/CN=Test Identity Provider' -keyout idp-private-key.pem -out idp-public-cert.pem -days 7300"
    }

    argv.cert = fs.readFileSync(argv.cert);
    argv.key = fs.readFileSync(argv.key);
    return true;
  })
  .check(function(argv, aliases) {
    if (argv.https) {

      if (!fs.existsSync(argv.httpsPrivateKey)) {
        return 'HTTPS Private Key "' + argv.httpsPrivateKey + '" is not a valid file path';
      }

      if (!fs.existsSync(argv.httpsCert)) {
        return 'HTTPS Certificate "' + argv.httpsCert + '" is not a valid file path';
      }

      argv.httpsPrivateKey = fs.readFileSync(argv.httpsPrivateKey).toString();
      argv.httpsCert = fs.readFileSync(argv.httpsCert).toString();
    }
    return true;
  })
  .check(function(argv, aliases) {
    var hasFormat = function(file, header) {
      var data = fs.readFileSync(file);
      var re = new RegExp('-----BEGIN ' + header.toUpperCase() + '-----[^-]*-----END ' + header.toUpperCase() + '-----');
      return re.test(data);
    }

    if (argv.encryptionCert) {
      if (!fs.existsSync(argv.encryptionCert)) {
        return 'Encryption cert "' + argv.encryptionCert + '" is not a valid file path';
      }

      if (!hasFormat(argv.encryptionCert, 'CERTIFICATE')) {
        return 'Encryption cert "' + argv.encryptionCert + '" is not a valid PEM certificate';
      }

      if (argv.encryptionPublicKey === undefined) {
        return 'encryptionPublicKey argument is also required for assertion encryption';
      }
    }

    if (argv.encryptionPublicKey) {;
      if (!fs.existsSync(argv.encryptionPublicKey)) {
        return 'Encryption public key "' + argv.encryptionPublicKey + '" is not a valid file path';
      }

      if (!hasFormat(argv.encryptionPublicKey, 'PUBLIC KEY')) {
        return 'Encryption cert "' + argv.encryptionPublicKey + '" is not a valid PEM certificate';
      }

      if (argv.encryptionCert === undefined) {
        return 'encryptionCert argument is also required for assertion encryption';
      }

      // Set flag since both file args are present
      argv.encryptAssertion = true;
    }
    return true;
  })
  .argv;



console.log();
console.log('Listener Port:\n\t' + argv.port);
console.log('HTTPS Listener:\n\t' + argv.https);
console.log('IdP Issuer URI:\n\t' + argv.issuer);
console.log('SP ACS URL:\n\t' + argv.acsUrl);
console.log('SP Audience URI:\n\t' + argv.audience);
console.log('Default RelayState:\n\t' + argv.relayState);
console.log('Allow SP to Specify ACS URLs:\n\t' + !argv.disableRequestAcsUrl);
console.log('Assertion Encryption:\n\t' + argv.encryptAssertion);
console.log('Sign Response:\n\t' + argv.signResponse);
console.log();

/**
 * IdP Configuration
 */

SimpleProfileMapper.prototype.metadata = config.metadata;

var idpOptions = {
  issuer:                 argv.issuer,
  cert:                   fs.readFileSync(path.join(__dirname, 'idp-public-cert.pem')),
  key:                    fs.readFileSync(path.join(__dirname, 'idp-private-key.pem')),
  audience:               argv.audience,
  recipient:              argv.acsUrl,
  destination:            argv.acsUrl,
  acsUrl:                 argv.acsUrl,
  RelayState:             argv.relayState,
  allowRequestAcsUrl:     !argv.disableRequestAcsUrl,
  digestAlgorithm:        'sha256',
  signatureAlgorithm:     'rsa-sha256',
  signResponse:           argv.signResponse,
  encryptAssertion:       argv.encryptAssertion,
  encryptionAlgorithm:    'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
  keyEncryptionAlgorighm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
  lifetimeInSeconds:      3600,
  authnContextClassRef:   'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
  profileMapper:          SimpleProfileMapper,
  getUserFromRequest:     function(req) { return req.user; },
  getPostURL:             function (audience, authnRequestDom, req, callback) {
                            return callback(null, (req.authnRequest && req.authnRequest.acsUrl) ?
                              req.authnRequest.acsUrl :
                              argv.acsUrl);
                          }
}

if (argv.encryptAssertion) {
  idpOptions.encryptionCert = fs.readFileSync(argv.encryptionCert);
  idpOptions.encryptionPublicKey = fs.readFileSync(argv.encryptionPublicKey);
}

/**
 * App Environment
 */

app.set('port', process.env.PORT || argv.port);
app.set('views', path.join(__dirname, 'views'));

/**
 * View Engine
 */

app.set('view engine', 'hbs');
app.set('view options', { layout: 'layout' })
app.engine('handlebars', hbs.__express);

// Register Helpers
hbs.registerHelper('extend', function(name, context) {
    var block = blocks[name];
    if (!block) {
        block = blocks[name] = [];
    }

    block.push(context.fn(this));
});

hbs.registerHelper('block', function(name) {
    var val = (blocks[name] || []).join('\n');
    // clear the block
    blocks[name] = [];
    return val;
});


hbs.registerHelper('select', function(selected, options) {
    return options.fn(this).replace(
        new RegExp(' value=\"' + selected + '\"'),
        '$& selected="selected"');
});

hbs.registerHelper('getProperty', function(attribute, context) {
    return context[attribute];
});

hbs.registerHelper('serialize', function(context) {
  return new Buffer(JSON.stringify(context)).toString('base64');
});

/**
 * Middleware
 */

app.use(logger(':date> :method :url - {:referrer} => :status (:response-time ms)'));
app.use(bodyParser.urlencoded({extended: true}))
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));


/**
 * View Handlers
 */

const showUser = function (req, res, next) {
  res.render('user', {
    user: req.user,
    metadata: req.metadata,
    authnRequest: req.authnRequest,
    idp: req.idp.options
  });
}

/**
 * Shared Handlers
 */

const parseSamlRequest = function(req, res, next) {
  samlp.parseRequest(req, function(err, data) {
    if (err) {
      return res.render('error', {
        message: 'SAML AuthnRequest Parse Error: ' + err.message,
        error: err
      });
    };
    if (data) {
      req.authnRequest = {
        relayState: req.query.RelayState || req.body.RelayState,
        id: data.id,
        issuer: data.issuer,
        destination: data.destination,
        acsUrl: data.assertionConsumerServiceURL,
        forceAuthn: data.forceAuthn === 'true'
      };
      console.log('Received AuthnRequest => \n', req.authnRequest);
    }
    return showUser(req, res, next);
  })
};


/**
 * Routes
 */

app.use(function(req, res, next){
  req.user = config.user;
  req.metadata = config.metadata;
  req.idp = { options: idpOptions };
  next();
});

app.get(['/', '/idp'], parseSamlRequest);
app.post(['/', '/idp'], parseSamlRequest);

app.post('/sso', function(req, res) {
  var authOptions = extend({}, req.idp.options);
  console.log('here');
  Object.keys(req.body).forEach(function(key) {
    var buffer;
    if (key === '_authnRequest') {
      buffer = new Buffer(req.body[key], 'base64');
      req.authnRequest = JSON.parse(buffer.toString('utf8'));

      // Apply AuthnRequest Params
      authOptions.inResponseTo = req.authnRequest.id;
      if (req.idp.options.allowRequestAcsUrl && req.authnRequest.acsUrl) {
        authOptions.acsUrl = req.authnRequest.acsUrl;
        authOptions.recipient = req.authnRequest.acsUrl;
        authOptions.destination = req.authnRequest.acsUrl;
        authOptions.forceAuthn = req.authnRequest.forceAuthn;
      }
      if (req.authnRequest.relayState) {
        authOptions.RelayState = req.authnRequest.relayState;
      }
    } else {
      req.user[key] = req.body[key];
    }
  });

  if (!authOptions.encryptAssertion) {
    delete authOptions.encryptionCert;
    delete authOptions.encryptionPublicKey;
  }

  // Keep calm and Single Sign On
  console.log('Sending Assertion with Options => \n', authOptions);
  samlp.auth(authOptions)(req, res);
})

app.get('/metadata', function(req, res, next) {
  samlp.metadata(req.idp.options)(req, res);
});

app.post('/metadata', function(req, res, next) {
  if (req.body && req.body.attributeName && req.body.displayName) {
    var attributeExists = false;
    var attribute = {
      id: req.body.attributeName,
      optional: true,
      displayName: req.body.displayName,
      description: req.body.discription || '',
      multiValue: req.body.valueType === 'multi'
    };

    req.metadata.forEach(function(entry) {
      if (entry.id === req.body.attributeName) {
        entry = attribute;
        attributeExists = true;
      }
    });

    if (!attributeExists) {
      req.metadata.push(attribute);
    }
    console.log("Updated SAML Attribute Metadata => \n", req.metadata)
    res.status(200).end();
  }
});

app.get(['/settings'], function(req, res, next) {
  res.render('settings', {
    idp: req.idp.options
  });
});

app.post(['/settings'], function(req, res, next) {
  Object.keys(req.body).forEach(function(key) {
    switch(req.body[key].toLowerCase()){
      case "true": case "yes": case "1":
        req.idp.options[key] = true;
        break;
      case "false": case "no": case "0":
        req.idp.options[key] = false;
        break;
      default:
        req.idp.options[key] = req.body[key];
        break;
    }

    if (req.body[key].match(/^\d+$/)) {
      req.idp.options[key] = parseInt(req.body[key], '10');
    }
  });

  console.log('Updated IdP Configuration => \n', req.idp.options);
  res.redirect('/');
});

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Route Not Found');
  err.status = 404;
  next(err);
});

// development error handler
app.use(function(err, req, res, next) {
  if (err) {
    res.status(err.status || 500);
    res.render('error', {
        message: err.message,
        error: err
    });
  }
});

/**
 * Start IdP Web Server
 */

console.log('starting server...');
httpServer = argv.https ?
  https.createServer({ key: argv.httpsPrivateKey, cert: argv.httpsCert }, app) :
  http.createServer(app);


httpServer.listen(app.get('port'), function() {
  var scheme   = argv.https ? 'https' : 'http',
      address  = httpServer.address(),
      hostname = os.hostname();
      baseUrl  = address.address === '0.0.0.0' ?
        scheme + '://' + hostname + ':' + address.port :
        scheme + '://localhost:' + address.port;

  console.log('listening on port: ' + app.get('port'));
  console.log();
  console.log('SAML IdP Metadata: ');
  console.log('\t=> ' + baseUrl + '/metadata');
  console.log('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST');
  console.log('\t=> ' + baseUrl + '/idp')
  console.log('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect');
  console.log('\t=> ' + baseUrl + '/idp')
  console.log();
});
