using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace BasicOktaPasswordTokenFlow
{
    public sealed class OktaClient
    {
        private const string ApiPrefix = "api/v1";
        private const string DefaultPasswordGrantScopes = "openid offline_access";

        private readonly string _orgUrl;
        private readonly string _apiToken;

        private readonly HttpClient _httpClient;

        public OktaClient(string orgUrl, string apiToken)
        {
            if (string.IsNullOrEmpty(orgUrl))
            {
                throw new ArgumentNullException(nameof(orgUrl));
            }

            if (string.IsNullOrEmpty(apiToken))
            {
                throw new ArgumentNullException(nameof(apiToken));
            }

            _apiToken = apiToken;
            _orgUrl = EnsureCorrectOrgUrl(orgUrl);

            _httpClient = CreateClient(_orgUrl);
        }

        private static string EnsureCorrectOrgUrl(string orgUrl)
        {
            if (!orgUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("Org URL must start with https://");
            }

            if (!orgUrl.EndsWith("/"))
            {
                orgUrl += "/";
            }

            return orgUrl;
        }

        private static HttpClient CreateClient(string orgBaseUrl)
        {
            var handler = new HttpClientHandler
            {
                AllowAutoRedirect = false
            };

            var client = new HttpClient(handler, true)
            {
                BaseAddress = new Uri(orgBaseUrl, UriKind.Absolute)
            };

            // Workaround for https://github.com/dotnet/corefx/issues/11224
            client.DefaultRequestHeaders.Add("Connection", "close");

            return client;
        }

        private async Task<T> GetResource<T>(string path, CancellationToken cancellationToken)
        {
            // orgUrl already is guaranteed to have a trailing slash
            var sanitizedResourcePath = path.TrimStart('/');

            using (var request = new HttpRequestMessage(HttpMethod.Get, sanitizedResourcePath))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("SSWS", _apiToken);
                return await SendAsync<T>(request, cancellationToken);
            }
        }

        private async Task<T> SendAsync<T>(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            using (var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false))
            {
                var json = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                response.EnsureSuccessStatusCode();

                return JsonConvert.DeserializeObject<T>(json);
            }
        }

        public Task<User> GetUserAsync(string userId, CancellationToken cancellationToken)
            => GetResource<User>($"{ApiPrefix}/users/{userId}", cancellationToken);

        public async Task<GrantResult> PostPasswordGrantAsync(
            string authorizationServerId,
            string clientId,
            string clientSecret,
            string username,
            string password,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            var url = $"oauth2/{authorizationServerId}/v1/token";

            using (var request = new HttpRequestMessage(HttpMethod.Post, url))
            {
                var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}"));
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);

                var parameters = new Dictionary<string, string>()
                {
                    ["grant_type"] = "password",
                    ["scope"] = DefaultPasswordGrantScopes,
                    ["username"] = username,
                    ["password"] = password
                };
                request.Content = new FormUrlEncodedContent(parameters);

                return await SendAsync<GrantResult>(request, cancellationToken);
            }
        }

        public async Task<GrantResult> PostRefreshGrantAsync(
            string authorizationServerId,
            string clientId,
            string clientSecret,
            string refreshToken,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            var url = $"oauth2/{authorizationServerId}/v1/token";

            using (var request = new HttpRequestMessage(HttpMethod.Post, url))
            {
                var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}"));
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);

                var parameters = new Dictionary<string, string>()
                {
                    ["grant_type"] = "refresh_token",
                    ["refresh_token"] = refreshToken
                };
                request.Content = new FormUrlEncodedContent(parameters);

                return await SendAsync<GrantResult>(request, cancellationToken);
            }
        }

        public async Task<TokenIntrospectionResult> IntrospectTokenAsync(
            string authorizationServerId,
            string clientId,
            string clientSecret,
            string token,
            string tokenType,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            var url = $"oauth2/{authorizationServerId}/v1/introspect";

            using (var request = new HttpRequestMessage(HttpMethod.Post, url))
            {
                var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}"));
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);

                var parameters = new Dictionary<string, string>()
                {
                    ["token"] = token,
                    ["token_type_hint"] = tokenType
                };
                request.Content = new FormUrlEncodedContent(parameters);

                return await SendAsync<TokenIntrospectionResult>(request, cancellationToken);
            }
        }
    }
}
