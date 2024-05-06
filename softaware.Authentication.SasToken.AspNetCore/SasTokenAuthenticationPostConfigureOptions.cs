using Microsoft.Extensions.Options;
using softaware.Authentication.SasToken.Generators;

namespace softaware.Authentication.SasToken.AspNetCore
{
    public class SasTokenAuthenticationPostConfigureOptions(SasTokenSignatureGenerator? signatureGenerator = null)
        : IPostConfigureOptions<SasTokenAuthenticationSchemeOptions>
    {
        private readonly SasTokenSignatureGenerator? signatureGenerator = signatureGenerator;

        public void PostConfigure(string? name, SasTokenAuthenticationSchemeOptions options)
        {
            if (this.signatureGenerator == null)
            {
                throw new InvalidOperationException($"A {nameof(SasTokenSignatureGenerator)} must be registered in the dependency injection container.");
            }

            options.SignatureGenerator = this.signatureGenerator;
        }
    }
}
