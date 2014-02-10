function SimpleProfileMapper (pu) {
  if(!(this instanceof SimpleProfileMapper)) {
    return new SimpleProfileMapper(pu);
  }
  this._pu = pu;
  this.nameIdFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
}

SimpleProfileMapper.prototype.getClaims = function() {
  var claims = {};

  claims[this.nameIdFormat]  = this._pu.id;
  claims['Email']      = this._pu.email;
  claims['FirstName']  = this._pu.firstName
  claims['LastName']    = this._pu.lastName;
 
  return claims;
};

SimpleProfileMapper.prototype.getNameIdentifier = function() {
  return { nameIdentifier: this.getClaims()[this.nameIdFormat] };
};


SimpleProfileMapper.prototype.metadata = [ {
  id: "Email",
  optional: true,
  displayName: 'E-Mail Address',
  description: 'The e-mail address of the user'
}, {
  id: "FirstName",
  optional: true,
  displayName: 'First Name',
  description: 'The given name of the user'
}, {
  id: "LastName",
  optional: true,
  displayName: 'Last Name',
  description: 'The surname of the user'
}];

module.exports = SimpleProfileMapper;