function SimpleProfileMapper (pu) {
  if(!(this instanceof SimpleProfileMapper)) {
    return new SimpleProfileMapper(pu);
  }
  this._pu = pu;
}

SimpleProfileMapper.prototype.getClaims = function() {
  var claims = {};

  claims['Email']         = this._pu.email;
  claims['FirstName']     = this._pu.firstName
  claims['LastName']      = this._pu.lastName;
  claims['DisplayName']   = this._pu.displayName;
  claims['MobilePhone']   = this._pu.mobilePhone;
  if (this._pu.groups) {
    claims['Groups']      = this._pu.groups.split(',');
  }
  
  return claims;
};

SimpleProfileMapper.prototype.getNameIdentifier = function() {
  return { 
    nameIdentifier:                  this._pu.userName,
    nameIdentifierFormat:            this._pu.nameIdFormat,
    nameIdentifierNameQualifier:     this._pu.nameIdNameQualifier,
    nameIdentifierSPNameQualifier:   this._pu.nameIdSPNameQualifier,
    nameIdentifierSPProvidedID:      this._pu.nameIdSPProvidedID
  };
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
}, {
  id: "DisplayName",
  optional: true,
  displayName: 'Display Name',
  description: 'The display name of the user'
}, {
  id: "MobilePhone",
  optional: true,
  displayName: 'Mobile Phone',
  description: 'The mobile phone of the user'
}, {
  id: "Groups",
  optional: true,
  displayName: 'Groups',
  description: 'Group memberships of the user'
}];

module.exports = SimpleProfileMapper;