using Microsoft.AspNetCore.Authentication;
using softaware.Authentication.SasToken.Generators;

namespace softaware.Authentication.SasToken.AspNetCore
{
    public class SasTokenAuthenticationSchemeOptions : AuthenticationSchemeOptions
    {
        public string AuthenticationScheme { get; set; }

        public SasTokenAuthenticationSchemeOptions()
        {
            this.AuthenticationScheme = SasTokenAuthenticationDefaults.AuthenticationScheme;
        }

        public SasTokenAuthenticationSchemeOptions(SasTokenSignatureGenerator signatureGenerator)
        {
            this.AuthenticationScheme = SasTokenAuthenticationDefaults.AuthenticationScheme;
        }
    }
}
