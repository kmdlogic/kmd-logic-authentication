using System;

namespace Kmd.Logic.Identity.Authorization
{
    /// <summary>
    /// Provide the configuration options for issuing an authorization token required to access Logic services.
    /// </summary>
    public sealed class LogicTokenProviderOptions
    {
        /// <summary>
        /// Gets or sets the Logic Identity authorization token issuer.
        /// </summary>
        /// <remarks>
        /// This option should not be overridden except for testing purposes.
        /// </remarks>
        public Uri AuthorizationTokenIssuer { get; set; }

        /// <summary>
        /// Gets or sets the Logic Identity authorization scope.
        /// </summary>
        public string AuthorizationScope { get; set; }

        /// <summary>
        /// Gets or sets the client credentials identifier.
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the client credentials secret.
        /// </summary>
        public string ClientSecret { get; set; }
    }
}