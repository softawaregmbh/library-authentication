using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace softaware.Authentication.Hmac.AuthorizationProvider
{
    public class MemoryHmacAuthenticationProvider : IHmacAuthorizationProvider
    {
        private IDictionary<string, string> hmacAuthenticatedApps;

        public MemoryHmacAuthenticationProvider(IDictionary<string, string> hmacAuthenticatedApps)
        {
            this.hmacAuthenticatedApps = hmacAuthenticatedApps ?? throw new ArgumentNullException(nameof(hmacAuthenticatedApps));
        }

        public Task<AuthorizationProviderResult> TryGetApiKeyAsync(string appId)
        {
            if (this.hmacAuthenticatedApps.TryGetValue(appId, out var apiKey))
            {
                return Task.FromResult(new AuthorizationProviderResult(appId, found: true, apiKey));
            }
            else
            {
                return Task.FromResult(new AuthorizationProviderResult(appId, found: false, apiKey: null));
            }
        }
    }
}
