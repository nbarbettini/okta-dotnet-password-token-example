# Simple Okta password flow example

This example demonstrates how to use the Okta OAuth 2.0/OpenID Connect API to generate an access token (JWT) for a user.

In order to run the sample, you must add some information to `App.config`:

* Set `OktaOrgHref` to your Okta organization URL, like `https://dev-123456.oktapreview.com`
* Generate an API token (Security - API - Tokens) and paste it in the `OktaApiToken` setting.
* If you haven't already, create a Native OpenID Connect application (Applications - Create New App - Native). The callback URI can be a dummy URI for now. Edit the general settings and **enable** the Resource Owner Password flow. Edit the credentials settings and switch to Client Authentication. Copy the Client ID into the `OktaAppClientId` setting, and the Client Secret to the `OktaAppClientSecret` setting.
* If you haven't already, create an Authorization Server (Security - API - Authorization Servers). The name and resource URI don't matter for now. Copy the **end** of the Issuer URI, after `.oktapreview.com/oauth2/` into the  `OktaAuthorizationServerId` setting. The ID will look like `aus8h593...`.

Create a test user (Directory - People) with an email address you control, and then use Reset Password to send a password reset email. Use the password reset flow (in a new browser or incognito window) to create a real password for your test user. Then, assign them to your application (Applications - (your app) - People).

Now you're ready to try out the sample! Build the project and run it to step through the flow.