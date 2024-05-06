using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using softaware.Authentication.SasToken.Generators;

namespace softaware.Authentication.SasToken.AspNetCore
{
    public class SasTokenAuthenticationSchemeOptions : AuthenticationSchemeOptions
    {
        public string AuthenticationScheme { get; set; }

        /// <summary>
        /// The name of the query parameter which will be populated as <see cref="ClaimTypes.NameIdentifier"/> claim type in the authenticated claims identity.
        /// The value of the query parameter will be used as the name identifier.
        /// <para>
        /// Use the <see cref="SasTokenUrlGenerator"/> overload which allows specifying query parameters to set a value for the claim.
        /// </para>
        /// </summary>
        public string? NameIdentifierQueryParameter { get; set; }

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
