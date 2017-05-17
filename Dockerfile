FROM node:latest 

ADD ./package.json package.json
RUN npm install -g bower
RUN npm install

ADD ./bower.json bower.json
RUN bower install --allow-root

EXPOSE 7000 7000 

# ADD ./node_modules node_modules
ADD ./lib lib
ADD ./views views
ADD ./app.js app.js
ADD ./config.js config.js
ADD ./idp-public-cert.pem idp-public-cert.pem
ADD ./idp-private-key.pem idp-private-key.pem

ENTRYPOINT [ "node",  "app.js", "--acs", "https://foo.okta.com/auth/saml20/example", "--aud", "https://www.okta.com/saml2/service-provider/spf5aFRRXFGIMAYXQPNV" ]
