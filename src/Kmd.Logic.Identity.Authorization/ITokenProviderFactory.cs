using System;
using System.Net.Http;
using Microsoft.Rest;

namespace Kmd.Logic.Identity.Authorization
{
    public interface ITokenProviderFactory : IDisposable
    {
        ITokenProvider GetProvider(HttpClient httpClient);
    }
}