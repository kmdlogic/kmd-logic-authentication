using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Rest;
using Microsoft.Rest.Serialization;
using Newtonsoft.Json;

namespace Kmd.Logic.Identity.Authorization
{
    /// <summary>
    /// Generate authorization tokens required to access Logic services.
    /// </summary>
    /// <remarks>
    /// The LogicTokenProviderFactory is intended to be a long-lived class.
    /// </remarks>
    public sealed class LogicTokenProviderFactory : IDisposable
    {
        private readonly LogicTokenProviderOptions options;
        private readonly SemaphoreSlim semaphore = new SemaphoreSlim(1, 1);
        private readonly JsonSerializerSettings jsonSerializerSettings = new JsonSerializerSettings();

        private DateTime expiration = DateTime.Now;
        private TokenResponse currentToken;

        /// <summary>
        /// Gets or sets the default authorization scope when not configured in <see cref="LogicTokenProviderOptions"/>.
        /// </summary>
        [Obsolete("Provided for backwards compatibility of existing packages. Instead set the AuthorizationScope in LogicTokenProviderOptions.")]
        public string DefaultAuthorizationScope { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="LogicTokenProviderFactory"/> class.
        /// </summary>
        /// <param name="options">The required configuration options.</param>
        public LogicTokenProviderFactory(LogicTokenProviderOptions options)
        {
            this.options = options ?? throw new ArgumentNullException(nameof(options));
        }

        /// <summary>
        /// Get a token provider which can issue authorization header.
        /// </summary>
        /// <param name="httpClient">The HTTP client to use. The caller is expected to manage this resource and it will not be disposed.</param>
        /// <returns>A authorization token provider.</returns>
        public ITokenProvider GetProvider(HttpClient httpClient)
        {
            return new TokenProvider(this, httpClient, this.jsonSerializerSettings);
        }

        internal class TokenProvider : ITokenProvider
        {
            private readonly LogicTokenProviderFactory parent;
            private readonly HttpClient httpClient;
            private readonly JsonSerializerSettings jsonSerializerSettings;

            public TokenProvider(LogicTokenProviderFactory parent, HttpClient httpClient, JsonSerializerSettings jsonSerializerSettings)
            {
                this.httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
                this.parent = parent;
                this.jsonSerializerSettings = jsonSerializerSettings;
            }

            public async Task<AuthenticationHeaderValue> GetAuthenticationHeaderAsync(CancellationToken cancellationToken)
            {
                await this.parent.semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    if (this.parent.currentToken != null && this.parent.expiration > DateTime.Now)
                    {
                        return new AuthenticationHeaderValue(this.parent.currentToken.TokenType, this.parent.currentToken.AccessToken);
                    }

                    this.parent.currentToken = null;

                    var expire = DateTime.Now;

                    var scope = this.parent.options.AuthorizationScope;
                    if (string.IsNullOrEmpty(scope))
                    {
#pragma warning disable CS0618 // Type or member is obsolete
                        scope = this.parent.DefaultAuthorizationScope;
#pragma warning restore CS0618 // Type or member is obsolete
                    }

                    var token = await this.RequestToken(
                        this.httpClient,
                        this.parent.options.AuthorizationTokenIssuer,
                        this.parent.options.ClientId,
                        scope,
                        this.parent.options.ClientSecret,
                        cancellationToken,
                        this.parent.options.Tenant)
                        .ConfigureAwait(false);

                    this.parent.expiration = expire.AddSeconds(token.ExpiresIn - 5);

                    if (string.IsNullOrEmpty(token.AccessToken))
                    {
                        throw new LogicTokenProviderException("Unable to get a token from the token issuer");
                    }

                    this.parent.currentToken = token;

                    return new AuthenticationHeaderValue(this.parent.currentToken.TokenType, this.parent.currentToken.AccessToken);
                }
                finally
                {
                    this.parent.semaphore.Release();
                }
            }

            private async Task<TokenResponse> RequestToken(
                HttpClient httpClient,
                Uri uriAuthorizationServer,
                string clientId,
                string scope,
                string clientSecret,
                CancellationToken cancellationToken,
                string Tenant = null)
            {
                HttpResponseMessage responseMessage;

                if (Tenant != null)
                {
                    UriBuilder uriBuilder = new UriBuilder(uriAuthorizationServer);
                    NameValueCollection query = HttpUtility.ParseQueryString(uriBuilder.Query);
                    query["Tenant"] = Tenant;
                    uriBuilder.Query = query.ToString();
                    uriAuthorizationServer = uriBuilder.Uri;
                }

                using (var tokenRequest = new HttpRequestMessage(HttpMethod.Post, uriAuthorizationServer))
                {
                    tokenRequest.Content = new FormUrlEncodedContent(
                        new[]
                        {
                            new KeyValuePair<string, string>("grant_type", "client_credentials"),
                            new KeyValuePair<string, string>("client_id", clientId),
                            new KeyValuePair<string, string>("scope", scope),
                            new KeyValuePair<string, string>("client_secret", clientSecret),
                        });

                    responseMessage = await httpClient.SendAsync(tokenRequest, cancellationToken).ConfigureAwait(false);

                    if (!responseMessage.IsSuccessStatusCode)
                    {
                        var message = $"Unable to access the token issuer, request returned {responseMessage.StatusCode}.";

                        TokenErrorResponse error = null;

                        try
                        {
                            var errorJson = await responseMessage
                                .Content
                                .ReadAsStringAsync()
                                .ConfigureAwait(false);

                            error = SafeJsonConvert.DeserializeObject<TokenErrorResponse>(errorJson, this.jsonSerializerSettings);
                        }
#pragma warning disable CA1031 // Do not catch general exception types
                        catch
                        {
                            // Do nothing
                        }
#pragma warning restore CA1031 // Do not catch general exception types

                        if (error != null && !string.IsNullOrEmpty(error.Error))
                        {
                            message += $" Reason: {error.Error}.";
                        }
                        else if (responseMessage.StatusCode == HttpStatusCode.Unauthorized)
                        {
                            message += " Your client credentials may be invalid or are not authorized to request the scope.";
                        }

                        throw new LogicTokenProviderException(message);
                    }

                    var json = await responseMessage
                        .Content
                        .ReadAsStringAsync()
                        .ConfigureAwait(false);

                    return SafeJsonConvert.DeserializeObject<TokenResponse>(json, this.jsonSerializerSettings);
                }
            }
        }

        public void Dispose()
        {
            this.semaphore.Dispose();
        }
    }
}