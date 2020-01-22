# KMD Logic Identity Authorization

A dotnet library which authenticates service requests using Logic Identity.

## How to use this client library

In projects or components where you need to use services authenticated with Logic Identity, add a NuGet package reference to [Kmd.Logic.Identity.Authorization](https://www.nuget.org/packages/Kmd.Logic.Identity.Authorization).

The `LogicTokenProviderFactory` authorizes access through the use of a Logic Identity issued client credential. The authorization token is reused until it  expires. You would generally create a single instance of `LogicTokenProviderFactory`.

## How to configure the LogicTokenProviderFactory

Perhaps the easiest way to configure the LogicTokenProviderFactory is from Application Settings.

```json
{
  "TokenProvider": {
    "ClientId": "",
    "ClientSecret": "",
    "AuthorizationScope": ""
  }
}
```

To get started:

1. Create a subscription in [Logic Console](https://console.kmdlogic.io). This will provide you the `SubscriptionId` which will be linked to the client credentials.
2. Request a client credential. Once issued you can view the `ClientId`, `ClientSecret` and `AuthorizationScope` in [Logic Console](https://console.kmdlogic.io).

## Calling Logic services using LogicTokenProviderFactory

You can generate a service client from the OpenAPI specification provided by Logic services using [Autorest](https://github.com/Azure/autorest).
These clients accept a `ServiceClientCredentials` from [Microsoft.Rest.ClientRuntime](https://www.nuget.org/packages/Microsoft.Rest.ClientRuntime).

Assuming you have generated a client called `LogicServiceClient`, the following will use the `LogicTokenProviderFactory` to issue a bearer token for each request.

```csharp
// Create the LogicTokenProviderFactory once
var options = new LogicTokenProviderOptions { ClientId = "<your client id>", ClientSecret = "<your client secret>" };
var tokenProviderFactory = new LogicTokenProviderFactory(options);

// Create a token provider for each service client
var tokenProvider = this.tokenProviderFactory.GetProvider(this.httpClient);

var serviceClient = new LogicServiceClient(new TokenCredentials(tokenProvider))
{
    BaseUri = new Uri("https://gateway.kmdlogic.io/service/v1")
};
```

## Sample application

A simple console application is included to demonstrate how to authorize an application using Logic Identity. You will need to provide the settings described above in `appsettings.json`.

When run you should see the details of the issued Javascript Web Token (JWT) printed to the console.

## Breaking Change in Version 1.1.0

In version 1.1.0 of this library, the default value for LogicTokenProviderOptions.AuthorizationScope was removed.

For dependent packages which need to maintain backward compatibility, you can set the DefaultAuthorizationScope as below.

```csharp
#pragma warning disable CS0618 // Type or member is obsolete
    if (string.IsNullOrEmpty(this.tokenProviderFactory.DefaultAuthorizationScope))
    {
        this.tokenProviderFactory.DefaultAuthorizationScope = "https://logicidentityprod.onmicrosoft.com/bb159109-0ccd-4b08-8d0d-80370cedda84/.default";
    }
#pragma warning restore CS0618 // Type or member is obsolete
```