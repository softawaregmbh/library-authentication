using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace softaware.Authentication.Hmac.AuthorizationProvider
{
    public class MemoryHmacAuthenticationProvider : IHmacAuthorizationProvider
    {
        private readonly Dictionary<string, string[]> hmacAuthenticatedApps;

        public MemoryHmacAuthenticationProvider(IDictionary<string, string> hmacAuthenticatedApps)
        {
            if (hmacAuthenticatedApps == null)
            {
                throw new ArgumentNullException(nameof(hmacAuthenticatedApps));
            }

            this.hmacAuthenticatedApps = hmacAuthenticatedApps.ToDictionary(
                kvp => kvp.Key,
                kvp => new[] { kvp.Value });
        }

        /// <summary>
        /// Initializes a new instance with multiple API keys per AppId to support key rotation.
        /// </summary>
        public MemoryHmacAuthenticationProvider(IDictionary<string, IList<string>> hmacAuthenticatedApps)
        {
            if (hmacAuthenticatedApps == null)
            {
                throw new ArgumentNullException(nameof(hmacAuthenticatedApps));
            }

            this.hmacAuthenticatedApps = hmacAuthenticatedApps.ToDictionary(
                kvp => kvp.Key,
                kvp => kvp.Value.ToArray());
        }

        public Task<AuthorizationProviderResult> TryGetApiKeyAsync(string appId)
        {
            if (this.hmacAuthenticatedApps.TryGetValue(appId, out var apiKeys))
            {
                return Task.FromResult(new AuthorizationProviderResult(appId, found: true, apiKeys));
            }
            else
            {
                return Task.FromResult(new AuthorizationProviderResult(appId, found: false, apiKey: null));
            }
        }
    }
}
