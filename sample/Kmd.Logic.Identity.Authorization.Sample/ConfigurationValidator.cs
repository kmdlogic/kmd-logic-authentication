using System;
using Serilog;

namespace Kmd.Logic.Identity.Authorization.Sample
{
    internal class ConfigurationValidator
    {
        private AppSettings configuration;

        public ConfigurationValidator(AppSettings configuration)
        {
            this.configuration = configuration;
        }

        public bool Validate()
        {
            if (string.IsNullOrEmpty(this.configuration.ClientId)
                || string.IsNullOrEmpty(this.configuration.ClientSecret)
                || string.IsNullOrEmpty(this.configuration.AuthorizationScope))
            {
                Log.Error(
                    "Invalid configuration. Please provide proper information to `appsettings.json`. Current data is: {@Settings}",
                    this.configuration);

                return false;
            }

            return true;
        }
    }
}