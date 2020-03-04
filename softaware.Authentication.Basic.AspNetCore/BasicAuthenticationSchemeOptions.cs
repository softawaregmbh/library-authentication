using Microsoft.AspNetCore.Authentication;
using softaware.Authentication.Basic.AspNetCore.AuthorizationProvider;

namespace softaware.Authentication.Basic.AspNetCore
{
    public class BasicAuthenticationSchemeOptions : AuthenticationSchemeOptions
    {
        public string AuthenticationScheme { get; set; }

        public IBasicAuthorizationProvider AuthorizationProvider { get; set; }

        /// <summary>
        /// Add password as claim after successfull authentication
        /// Security risks should be weighed up.
        /// </summary>
        public bool AddPasswordAsClaim { get; set; }

        /// <summary>
        /// Define password claim type if it will be added.
        /// <para/>Default - <see cref="BasicAuthenticationDefaults.PasswordClaimType" />
        /// </summary>
        public string PasswordClaimType { get; set; } = BasicAuthenticationDefaults.PasswordClaimType;

        public BasicAuthenticationSchemeOptions()
        {
            this.AuthenticationScheme = BasicAuthenticationDefaults.AuthenticationScheme;
        }

        public BasicAuthenticationSchemeOptions(IBasicAuthorizationProvider basicAuthorizationProvider)
        {
            this.AuthenticationScheme = BasicAuthenticationDefaults.AuthenticationScheme;
            this.AuthorizationProvider = basicAuthorizationProvider;
        }
    }
}
