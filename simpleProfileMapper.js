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

module.exports = SimpleProfileMapper;