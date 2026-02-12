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
        [Obsolete("Use the ClaimsQueryParameters property to specify claims to include in the authenticated claims identity instead.")]
        public string? NameIdentifierQueryParameter
        {
            get => this.ClaimsQueryParameters.TryGetValue(ClaimTypes.NameIdentifier, out var value) ? value : null;
            set
            {
                if (value == null)
                {
                    this.ClaimsQueryParameters.Remove(ClaimTypes.NameIdentifier);
                }
                else
                {
                    this.ClaimsQueryParameters.TryAdd(ClaimTypes.NameIdentifier, value);
                }
            }
        }

        /// <summary>
        /// A collection of claims to include in the authenticated claims identity.
        /// The key of the dictionary is the name of the claim, the value is the query paramter name which will be populated as the claim value in the authenticated claims identity.
        /// </summary>
        public IDictionary<string, string> ClaimsQueryParameters { get; set; } = new Dictionary<string, string>();

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
