
/**
 * Module dependencies.
 */

const express             = require('express'),
      os                  = require('os'),
      fs                  = require('fs'),
      http                = require('http'),
      https               = require('https'),
      basicauth           = require('express-basic-auth'),
      path                = require('path'),
      extend              = require('extend'),
      hbs                 = require('hbs'),
      logger              = require('morgan'),
      cookieParser        = require('cookie-parser'),
      bodyParser          = require('body-parser'),
      session             = require('express-session'),
      samlp               = require('samlp'),
      yargs               = require('yargs'),
      SimpleProfileMapper = require('./lib/simpleProfileMapper.js');

/**
 * Globals
 */

const cryptTypes           = {
      certificate: /-----BEGIN CERTIFICATE-----[^-]*-----END CERTIFICATE-----/,
      'RSA private key': /-----BEGIN RSA PRIVATE KEY-----\n[^-]*\n-----END RSA PRIVATE KEY-----/,
      'public key': /-----BEGIN PUBLIC KEY-----\n[^-]*\n-----END PUBLIC KEY-----/,
    },
    KEY_CERT_HELP_TEXT = "Please generate a key-pair for the IdP using the following openssl command:\n" +
      "\topenssl req -x509 -new -newkey rsa:2048 -nodes -subj '/C=US/ST=California/L=San Francisco/O=JankyCo/CN=Test Identity Provider' -keyout idp-private-key.pem -out idp-public-cert.pem -days 7300";


function matchesCertType(value, type) {
  // console.info(`Testing ${cryptTypes[type].toString()} against "${value}"`);
  // console.info(`result: ${cryptTypes[type] && cryptTypes[type].test(value)}`);
  return cryptTypes[type] && cryptTypes[type].test(value);
}

function bufferFromString(value) {
  if (Buffer.hasOwnProperty('from')) {
    // node 6+
    return Buffer.from(value);
  } else {
    return new Buffer(value);
  }
}

function resolveFilePath(filePath) {
  var possiblePath;
  if (fs.existsSync(filePath)) {
    return filePath;
  }
  if (filePath.slice(0, 2) === '~/') {
    possiblePath = path.resolve(process.env.HOME, filePath.slice(2));
    if (fs.existsSync(possiblePath)) {
      return possiblePath;
    } else {
      // for ~/ paths, don't try to resolve further
      return filePath;
    }
  }
  ['.', __dirname].forEach(function (base) {
    possiblePath = path.resolve(base, filePath);
    if (fs.existsSync(possiblePath)) {
      return possiblePath;
    }
  });
  return null;
}

function makeCertFileCoercer(type, description, helpText) {
  return function certFileCoercer(value) {
    if (matchesCertType(value, type)) {
      return value;
    }

    const filePath = resolveFilePath(value);
    if (filePath) {
      return fs.readFileSync(filePath)
    }
    throw new Error(
      'Invalid ' + description + ', not a valid crypt cert/key or file path' +
      (helpText ? '\n' + helpText : '')
    )
  };
}

function getHashCode(str) {
  var hash = 0;
  if (str.length == 0) return hash;
  for (i = 0; i < str.length; i++) {
    char = str.charCodeAt(i);
    hash = ((hash<<5)-hash)+char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return hash;
}


/**
 * Arguments
 */
function processArgs(options) {
  var baseArgv;
  console.log();
  console.log('loading configuration...');

  if (options) {
    baseArgv = yargs.config(options);
  } else {
    baseArgv = yargs.config('settings', function(settingsPathArg) {
      const settingsPath = resolveFilePath(settingsPathArg);
      return JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
    });
  }
  return baseArgv
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
        default: './idp-public-cert.pem',
        coerce: makeCertFileCoercer('certificate', 'IdP Signature PublicKey Certificate', KEY_CERT_HELP_TEXT)
      },
      key: {
        description: 'IdP Signature PrivateKey Certificate',
        required: true,
        default: './idp-private-key.pem',
        coerce: makeCertFileCoercer('RSA private key', 'IdP Signature PrivateKey Certificate', KEY_CERT_HELP_TEXT)
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
      encryptAssertion: {
        description: 'Encrypts assertion with SP Public Key',
        required: false,
        boolean: true,
        alias: 'enc',
        default: false
      },
      encryptionCert: {
        description: 'SP Certificate (pem) for Assertion Encryption',
        required: false,
        string: true,
        alias: 'encCert',
        coerce: makeCertFileCoercer('certificate', 'Encryption cert')
      },
      encryptionPublicKey: {
        description: 'SP RSA Public Key (pem) for Assertion Encryption ' +
        '(e.g. openssl x509 -pubkey -noout -in sp-cert.pem)',
        required: false,
        string: true,
        alias: 'encKey',
        coerce: makeCertFileCoercer('public key', 'Encryption public key')
      },
      httpsPrivateKey: {
        description: 'Web Server TLS/SSL Private Key (pem)',
        required: false,
        string: true,
        coerce: makeCertFileCoercer('RSA private key')
      },
      httpsCert: {
        description: 'Web Server TLS/SSL Certificate (pem)',
        required: false,
        string: true,
        coerce: makeCertFileCoercer('certificate')
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
        default: true,
        alias: 'signResponse'
      },
      configFile: {
        description: 'Path to a SAML attribute config file',
        required: true,
        default: require.resolve('./config.js'),
        alias: 'conf'
      },
      rollSession: {
        description: 'Create a new session for every authn request instead of reusing an existing session',
        required: false,
        boolean: true,
        default: false
      },
      bascicUser: {
        description: 'basic authentication user',
        required: false,
        alias: 'user'
      },
      bascicPass: {
        description: 'basic authentication password',
        required: false,
        default: '',
        alias: 'pass'
      }
    })
    .example('\t$0 --acs http://acme.okta.com/auth/saml20/exampleidp --aud https://www.okta.com/saml2/service-provider/spf5aFRRXFGIMAYXQPNV', '')
    .check(function(argv, aliases) {
      if (argv.encryptAssertion) {
        if (argv.encryptionPublicKey === undefined) {
          return 'encryptionPublicKey argument is also required for assertion encryption';
        }
        if (argv.encryptionCert === undefined) {
          return 'encryptionCert argument is also required for assertion encryption';
        }
      }
      return true;
    })
    .check(function(argv, aliases) {
      if (argv.config) {
        return true;
      }
      const configFilePath = resolveFilePath(argv.configFile);

      if (!configFilePath) {
        return 'SAML attribute config file path "' + argv.configFile + '" is not a valid path.\n';
      }
      try {
        argv.config = require(configFilePath);
      } catch (error) {
        return 'Encountered an exception while loading SAML attribute config file "' + configFilePath + '".\n' + error;
      }
      return true;
    })
    .wrap(yargs.terminalWidth());
}


function _runServer(argv) {
  const app = express();
  const httpServer = argv.https ?
    https.createServer({ key: argv.httpsPrivateKey, cert: argv.httpsCert }, app) :
    http.createServer(app);
  const blocks = {};

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
  if (argv.bascicUser) {
    var users = {};
    users[argv.bascicUser] = argv.bascicPass;
    console.log('BASIC Auth User:\n\t' + argv.bascicUser);
    app.use(basicauth({
      users: users,
      challenge: true,
      realm: 's3pJw9oDjq'
    }));
  }
  console.log();

  /**
   * IdP Configuration
   */

  SimpleProfileMapper.prototype.metadata = argv.config.metadata;

  const idpOptions = {
    issuer:                 argv.issuer,
    cert:                   argv.cert,
    key:                    argv.key,
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
    keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
    lifetimeInSeconds:      3600,
    authnContextClassRef:   'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
    includeAttributeNameFormat: true,
    profileMapper:          SimpleProfileMapper,
    getUserFromRequest:     function(req) { return req.user; },
    getPostURL:             function (audience, authnRequestDom, req, callback) {
                              return callback(null, (req.authnRequest && req.authnRequest.acsUrl) ?
                                req.authnRequest.acsUrl :
                                argv.acsUrl);
                            }
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
  app.use('/bower_components', express.static(__dirname + '/bower_components'))

  // Register Helpers
  hbs.registerHelper('extend', function(name, context) {
    var block = blocks[name];
    if (!block) {
      block = blocks[name] = [];
    }

    block.push(context.fn(this));
  });

  hbs.registerHelper('block', function(name) {
    const val = (blocks[name] || []).join('\n');
    // clear the block
    blocks[name] = [];
    return val;
  });


  hbs.registerHelper('select', function(selected, options) {
    return options.fn(this).replace(
      new RegExp(' value=\"' + selected + '\"'), '$& selected="selected"');
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
  app.use(session({
    secret: 'The universe works on a math equation that never even ever really ends in the end',
    resave: false,
    saveUninitialized: true,
    name: 'idp_sid',
    cookie: { maxAge: 60000 }
  }));


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
    if (argv.rollSession) {
      req.session.regenerate(function(err) {
        return next();
      });
    } else {
      next()
    }
  });

  app.use(function(req, res, next){
    req.user = argv.config.user;
    req.user.sessionIndex = Math.abs(getHashCode(req.session.id));
    req.metadata = argv.config.metadata;
    req.idp = { options: idpOptions };
    next();
  });

  app.get(['/', '/idp'], parseSamlRequest);
  app.post(['/', '/idp'], parseSamlRequest);

  app.post('/sso', function(req, res) {
    const authOptions = extend({}, req.idp.options);
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

    // Set Session Index
    authOptions.sessionIndex = req.user.sessionIndex;

    // Keep calm and Single Sign On
    console.log('Sending SAML Response\nUser => \n%s\nOptions => \n',
      JSON.stringify(req.user, null, 2), authOptions);
    samlp.auth(authOptions)(req, res);
  })

  app.get('/metadata', function(req, res, next) {
    samlp.metadata(req.idp.options)(req, res);
  });

  app.post('/metadata', function(req, res, next) {
    if (req.body && req.body.attributeName && req.body.displayName) {
      var attributeExists = false;
      const attribute = {
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

  app.get('/signout', function(req, res, next) {
    req.session.destroy(function(err) {
      if (err) {
        throw err;
      }
      res.redirect('back');
    })
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
    const err = new Error('Route Not Found');
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

  console.log('starting idp server on port %s', app.get('port'));

  httpServer.listen(app.get('port'), function() {
    const scheme   = argv.https ? 'https' : 'http',
        address  = httpServer.address(),
        hostname = os.hostname();
        baseUrl  = address.address === '0.0.0.0' || address.address === '::' ?
          scheme + '://' + hostname + ':' + address.port :
          scheme + '://localhost:' + address.port;

    console.log();
    console.log('SAML IdP Metadata URL: ');
    console.log('\t=> ' + baseUrl + '/metadata');
    console.log();
    console.log('Bindings: ');
    console.log();
    console.log('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST');
    console.log('\t=> ' + baseUrl + '/idp')
    console.log('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect');
    console.log('\t=> ' + baseUrl + '/idp')
    console.log();
    console.log();
    console.log('idp server ready');
    console.log('\t=> ' + baseUrl);
    console.log();
  });
}

function runServer(options) {
  const args = processArgs(options);
  return _runServer(args.parse([]));
}

function main () {
  const args = processArgs();
  _runServer(args.argv);
}

module.exports = {
  runServer,
  main,
};

if (require.main === module) {
  main();
}
