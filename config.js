
/**
 * User Profiles
 */
var presets = [{
  userName: 'saml_1.jackson@example.com',
  nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  firstName: 'Saml 1',
  lastName: 'Jackson',
  displayName: 'saml1 jackson',
  email: 'saml1.jackson@example.com',
  mobilePhone: '+1-415-555-5141',
  groups: 'Simple IdP Users, West Coast Users, Cloud Users'
},{
  userName: 'saml_2.jackson@example.com',
  nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  firstName: 'Saml 2',
  lastName: 'Jackson',
  displayName: 'saml2 jackson',
  email: 'saml2.jackson@example.com',
  mobilePhone: '+1-415-555-5141',
  groups: 'Simple IdP Users, West Coast Users, Cloud Users'
},{
  userName: 'saml_3.jackson@example.com',
  nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  firstName: 'Saml 3',
  lastName: 'Jackson',
  displayName: 'saml3 jackson',
  email: 'saml3.jackson@example.com',
  mobilePhone: '+1-415-555-5141',
  groups: 'Simple IdP Users, West Coast Users, Cloud Users'
}]

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
}, {
  id: "userType",
  optional: true,
  displayName: 'User Type',
  description: 'The type of user',
  options: ['Admin', 'Editor', 'Commenter']
}];

module.exports = {
  user: presets[0],
  presets: presets,
  metadata: metadata
}
