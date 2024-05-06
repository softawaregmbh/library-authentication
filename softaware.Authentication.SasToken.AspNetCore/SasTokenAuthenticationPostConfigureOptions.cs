using Microsoft.Extensions.Options;
using softaware.Authentication.SasToken.KeyProvider;

namespace softaware.Authentication.SasToken.AspNetCore
{
    public class SasTokenAuthenticationPostConfigureOptions(IKeyProvider? keyProvider = null)
        : IPostConfigureOptions<SasTokenAuthenticationSchemeOptions>
    {
        private readonly IKeyProvider? keyProvider = keyProvider;

        public void PostConfigure(string? name, SasTokenAuthenticationSchemeOptions options)
        {
            if (this.keyProvider == null)
            {
                throw new InvalidOperationException($"An {nameof(IKeyProvider)} must be registered in the dependency injection container.");
            }
        }
    }
}
