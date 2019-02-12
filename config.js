
/**
 * User Profile
 */
var profile = {
  userName: '******@buysell-technologies.com',
  nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  firstName: 'Hisahiro',
  lastName: 'Tsukamoto',
  displayName: 'buysell',
  email: '******@buysell-technologies.com',
  mobilePhone: '+1-415-555-5141',
  groups: 'Simple IdP Users, Cloud Users'
}

/**
 * SAML Attribute Metadata
 */
 var metadata = [{
   id: "User.LastName",
   optional: false,
   displayName: 'Last Name',
   description: 'The given name of the user',
   multiValue: false
 }, {
   id: "User.FirstName",
   optional: false,
   displayName: 'First Name',
   description: 'The surname of the user',
   multiValue: false
 }, {
   id: "employee_number",
   optional: true,
   displayName: 'employee number',
   description: 'The display name of the user',
   multiValue: false
 }, {
   id: "location",
   optional: false,
   displayName: 'location',
   description: 'The e-mail address of the user',
   multiValue: false
 },{
   id: "position",
   optional: false,
   displayName: 'position',
   description: 'The mobile phone of the user',
   multiValue: false
 }];

module.exports = {
  user: profile,
  metadata: metadata
}
