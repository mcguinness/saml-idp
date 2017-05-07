FROM node:latest 

ADD ./package.json package.json
RUN npm install -g bower
RUN npm install

ADD ./bower.json bower.json
RUN bower install --allow-root

RUN openssl req -x509 -new -newkey rsa:2048 -nodes -subj '/C=US/ST=California/L=San Francisco/O=JankyCo/CN=Test Identity Provider' -keyout idp-private-key.pem -out idp-public-cert.pem -days 7300

EXPOSE 7000 7000 

# ADD ./node_modules node_modules
ADD ./lib lib
ADD ./views views
ADD ./app.js app.js
ADD ./config.js config.js

ENTRYPOINT [ "node",  "app.js", "--acs", "https://foo.okta.com/auth/saml20/example", "--aud", "https://www.okta.com/saml2/service-provider/spf5aFRRXFGIMAYXQPNV" ]
