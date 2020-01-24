using System;

namespace Kmd.Logic.Identity.Authorization.Sample
{
    public class AppSettings
    {
        public Uri AuthorizationTokenIssuer { get; set; }

        public string AuthorizationScope { get; set; }

        public string ClientId { get; set; }

        public string ClientSecret { get; set; }
    }
}
