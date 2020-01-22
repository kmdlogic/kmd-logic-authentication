using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
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
        private static readonly Uri IdentityB2CServer = new Uri("https://identity-api.kmdlogic.io/clientcredentials/token");
        private static readonly Uri IdentityADServer = new Uri("https://login.microsoftonline.com/logicidentityprod.onmicrosoft.com/oauth2/v2.0/token");

        private readonly LogicTokenProviderOptions options;
        private readonly SemaphoreSlim semaphore = new SemaphoreSlim(1, 1);
        private readonly JsonSerializerSettings jsonSerializerSettings = new JsonSerializerSettings();

        private DateTime expiration = DateTime.Now;
        private TokenResponse currentToken;

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

                    var token = await this.RequestToken(
                        this.httpClient,
                        this.parent.options.AuthorizationTokenIssuer,
                        this.parent.options.ClientId,
                        this.parent.options.AuthorizationScope,
                        this.parent.options.ClientSecret,
                        cancellationToken)
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

            private async Task<TokenResponse> RequestToken(HttpClient httpClient, Uri uriAuthorizationServer, string clientId, string scope, string clientSecret, CancellationToken cancellationToken)
            {
                var server = uriAuthorizationServer;

                if (server == null)
                {
                    if (string.IsNullOrEmpty(scope))
                    {
                        throw new LogicTokenProviderException("No authorization scope is defined");
                    }

                    if (scope.EndsWith("/.default", StringComparison.Ordinal))
                    {
                        // The default scope issued by Active Directory is ".default"
                        // Assume the underlying provider of the client credential is AD
                        server = IdentityADServer;
                    }
                    else
                    {
                        // Assume the underlying provider of the client credential is B2C
                        server = IdentityB2CServer;
                    }
                }

                HttpResponseMessage responseMessage;

                using (var tokenRequest = new HttpRequestMessage(HttpMethod.Post, server))
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