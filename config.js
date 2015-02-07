
/**
 * User Profile
 */
var userProfile = {
	// SAML Subject ID == Okta Login
	userName: 'saml.jackson@example.com',
	nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
	firstName: 'Saml',
	lastName: 'Jackson',
	displayName: '¿Saml Jackson?',
	email: 'saml.jackson@example.com',
	mobilePhone: '+1-415-555-5141',
	groups: 'Simple IdP Users, West Coast Users, Cloud Users'
}

module.exports = {
	user: userProfile,
}
