
/**
 * User Profile
 */
var profile = {
  userName: 'saml.jackson@example.com',
  nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  firstName: 'Saml',
  lastName: 'Jackson',
  displayName: 'saml jackson',
  email: 'saml.jackson@example.com',
  mobilePhone: '+1-415-555-5141',
  groups: 'Simple IdP Users, West Coast Users, Cloud Users'
}

/**
 * SAML Attribute Metadata
 */
var metadata = [{
  id: "firstName",
  optional: false,
  displayName: 'First Name',
  description: 'The given name of the user',
  multiValue: false
}, {
  id: "lastName",
  optional: false,
  displayName: 'Last Name',
  description: 'The surname of the user',
  multiValue: false
}, {
  id: "displayName",
  optional: true,
  displayName: 'Display Name',
  description: 'The display name of the user',
  multiValue: false
}, {
  id: "email",
  optional: false,
  displayName: 'E-Mail Address',
  description: 'The e-mail address of the user',
  multiValue: false
},{
  id: "mobilePhone",
  optional: true,
  displayName: 'Mobile Phone',
  description: 'The mobile phone of the user',
  multiValue: false
}, {
  id: "groups",
  optional: true,
  displayName: 'Groups',
  description: 'Group memberships of the user',
  multiValue: true
}];

module.exports = {
  user: profile,
  metadata: metadata
}
