using Microsoft.AspNetCore.Authentication;
using softaware.Authentication.Basic.AspNetCore.AuthorizationProvider;

namespace softaware.Authentication.Basic.AspNetCore
{
    public class BasicAuthenticationSchemeOptions : AuthenticationSchemeOptions
    {
        public string AuthenticationScheme { get; set; }
        public IBasicAuthorizationProvider AuthorizationProvider { get; set; }

        public BasicAuthenticationSchemeOptions()
        {
            this.AuthenticationScheme = BasicAuthenticationDefaults.AuthenticationScheme;
        }
    }
}
