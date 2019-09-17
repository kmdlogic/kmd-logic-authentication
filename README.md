# KMD Logic Authentication Client

A dotnet library which authenticates Logic service requests.

## How to use this client library

In projects or components where you need to use Logic services, add a NuGet package reference to [Kmd.Logic.Authentication](https://www.nuget.org/packages/Kmd.Logic.Authentication).

The `LogicTokenProviderFactory` authorizes access to the Logic platform through the use of a Logic Identity issued client credential. The authorization token is reused until it  expires. You would generally create a single instance of `LogicTokenProviderFactory`.

## How to configure the LogicTokenProviderFactory 

Perhaps the easiest way to configure the LogicTokenProviderFactory is from Application Settings.

```json
{
  "TokenProvider": {
    "ClientId": "",
    "ClientSecret": ""
  }
}
```

To get started:

1. Create a subscription in [Logic Console](https://console.kmdlogic.io). This will provide you the `SubscriptionId`.
2. Request a client credential. Once issued you can view the `ClientId` and `ClientSecret` in [Logic Console](https://console.kmdlogic.io).

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
