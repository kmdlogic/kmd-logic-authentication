using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;
using Serilog;

namespace Kmd.Logic.Identity.Authorization.Sample
{
    public static class Program
    {
        public static async Task Main(string[] args)
        {
            InitLogger();

            try
            {
                var config = new ConfigurationBuilder()
                    .SetBasePath(AppContext.BaseDirectory)
                    .AddJsonFile("appsettings.json", optional: false)
                    .AddUserSecrets(typeof(Program).Assembly)
                    .AddEnvironmentVariables()
                    .AddCommandLine(args)
                    .Build()
                    .Get<AppSettings>();

                await Run(config).ConfigureAwait(false);
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
            {
                Log.Fatal(ex, "Caught a fatal unhandled exception");
            }
#pragma warning restore CA1031 // Do not catch general exception types
            finally
            {
                Log.CloseAndFlush();
            }
        }

        private static void InitLogger()
        {
            Log.Logger = new LoggerConfiguration()
                .Enrich.FromLogContext()
                .Destructure.ByTransforming<JsonWebToken>(jwt =>
                {
                    var result = new Dictionary<string, object>();

                    foreach (var claim in jwt.Claims)
                    {
                        if (result.TryGetValue(claim.Type, out var value))
                        {
                            var list = value as List<string>;

                            if (list == null)
                            {
                                list = new List<string>();
                                list.Add((string)value);
                                result[claim.Type] = list;
                            }

                            list.Add(claim.Value);
                        }
                        else
                        {
                            var claimValue = claim.Value;

                            switch (claim.Type)
                            {
                                case "exp":
                                case "nbf":
                                case "iat":
                                    if (long.TryParse(claimValue, out var timestamp))
                                    {
                                        var dt = DateTimeOffset.FromUnixTimeSeconds(timestamp).ToLocalTime();
                                        claimValue += $" (which is {dt})";
                                    }

                                    break;
                            }

                            result.Add(claim.Type, claimValue);
                        }
                    }

                    return result;
                })
                .WriteTo.Console()
                .CreateLogger();
        }

        private static async Task Run(AppSettings configuration)
        {
            var validator = new ConfigurationValidator(configuration);
            if (!validator.Validate())
            {
                return;
            }

            var options = new LogicTokenProviderOptions
            {
                ClientId = configuration.ClientId,
                ClientSecret = configuration.ClientSecret,
                Tenant = configuration.Tenant,
            };

            if (!string.IsNullOrEmpty(configuration.AuthorizationScope))
            {
                options.AuthorizationScope = configuration.AuthorizationScope;
            }

            if (configuration.AuthorizationTokenIssuer != null)
            {
                options.AuthorizationTokenIssuer = configuration.AuthorizationTokenIssuer;
            }

            using (var tokenFactory = new LogicTokenProviderFactory(options))
            using (var httpClient = new HttpClient())
            {
                var provider = tokenFactory.GetProvider(httpClient);

                Log.Information("Requesting access to scope {Scope} with client id {ClientId}", options.AuthorizationScope, options.ClientId);

                var authHeader = await provider.GetAuthenticationHeaderAsync(CancellationToken.None).ConfigureAwait(false);

                Log.Information("Retrieved authorization header {Scheme} {Parameter}", authHeader.Scheme, authHeader.Parameter);

                var jwt = new JsonWebToken(authHeader.Parameter);

                Log.Information("Deserialized JWT {@Jwt}", jwt);
            }
        }
    }
}