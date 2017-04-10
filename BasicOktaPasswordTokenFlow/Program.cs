using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BasicOktaPasswordTokenFlow
{
    class Program
    {
        static void Main(string[] args) => MainAsync().GetAwaiter().GetResult();

        private static async Task MainAsync()
        {
            // The info we need to connect to Okta
            var oktaOrgUrl = ConfigurationManager.AppSettings["OktaOrgHref"];
            var oktaApiToken = ConfigurationManager.AppSettings["OktaApiToken"];
            var oktaAppClientId = ConfigurationManager.AppSettings["OktaAppClientId"];
            var oktaAppClientSecret = ConfigurationManager.AppSettings["OktaAppClientSecret"];
            var oktaAuthorizationServerId = ConfigurationManager.AppSettings["OktaAuthorizationServerId"];

            // OktaClient just wraps up some of the repetitive functionality to make it easier to use
            var client = new OktaClient(oktaOrgUrl, oktaApiToken);

            // Exchange a username/password for a token (Password Grant)
            // Modify this to attempt a login with a real user's login and password
            var passwordGrantResult = await client.PostPasswordGrantAsync(
                oktaAuthorizationServerId, oktaAppClientId, oktaAppClientSecret,
                "test1@example.com",
                "Changeme123!!");

            Console.WriteLine("User logged in!");
            Console.WriteLine($"Access token: {passwordGrantResult.AccessToken}\n");
            Console.WriteLine($"Refresh token (if requested): {passwordGrantResult.RefreshToken}\n");

            var accessToken = passwordGrantResult.AccessToken;
            var refreshToken = passwordGrantResult.RefreshToken;

            // Later (on a separate request for example) we can verify that the
            // token is still valid by sending it up to Okta
            var introspectionResult = await client.IntrospectTokenAsync(
                oktaAuthorizationServerId, oktaAppClientId, oktaAppClientSecret,
                accessToken,
                "access_token");

            Console.WriteLine($"Token valid? {introspectionResult.Active}");

            // Alternatively, you could validate the RS256 (asymmetric) signature
            // locally, by inspecting the public key available on the OpenID configuration endpoint
            var keyProvider = new CachingJwksKeyProvider(
                $"{oktaOrgUrl}/oauth2/{oktaAuthorizationServerId}/.well-known/openid-configuration?client_id={oktaAppClientId}");
            var localValidator = new LocalAccessTokenValidator(keyProvider, oktaOrgUrl, oktaAuthorizationServerId, oktaAppClientId, oktaAppClientSecret);
            var localValidationResult = await localValidator.ValidateAsync(accessToken);

            Console.WriteLine($"Token valid (local check)? {introspectionResult.Active}\n");

            // Much later, when the access token expires, we can use the refresh token
            // to get a new access token (note that the refresh token only exists
            // if the "offline_access" scope is requested in the initial Password Grant flow)
            var refreshGrantResult = await client.PostRefreshGrantAsync(
                oktaAuthorizationServerId, oktaAppClientId, oktaAppClientSecret,
                refreshToken);

            Console.WriteLine($"Access token refreshed!\nNew access token: {refreshGrantResult.AccessToken}\n");

            Console.WriteLine("Done.");
            Console.ReadKey();
        }
    }
}
