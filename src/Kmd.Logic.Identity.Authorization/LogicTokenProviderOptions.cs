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
        public Uri AuthorizationTokenIssuer { get; set; } = new Uri("https://login.microsoftonline.com/logicidentityprod.onmicrosoft.com/oauth2/v2.0/token");

        /// <summary>
        /// Gets or sets the Logic Identity authorization scope.
        /// </summary>
        /// <remarks>
        /// This option should not be overridden except for testing purposes.
        /// </remarks>
        public string AuthorizationScope { get; set; } = "https://logicidentityprod.onmicrosoft.com/bb159109-0ccd-4b08-8d0d-80370cedda84/.default";

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