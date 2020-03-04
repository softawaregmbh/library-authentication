using Microsoft.Extensions.Options;
using softaware.Authentication.Basic.AspNetCore.AuthorizationProvider;

namespace softaware.Authentication.Basic.AspNetCore
{
    public class BasicAuthenticationPostConfigureOptions : IPostConfigureOptions<BasicAuthenticationSchemeOptions>
    {
        private readonly IBasicAuthorizationProvider basicAuthorizationProvider;

        public BasicAuthenticationPostConfigureOptions(IBasicAuthorizationProvider basicAuthorizationProvider = null)
        {
            this.basicAuthorizationProvider = basicAuthorizationProvider;
        }

        public void PostConfigure(string name, BasicAuthenticationSchemeOptions options)
        {
            if (this.basicAuthorizationProvider != null)
            {
                options.AuthorizationProvider = this.basicAuthorizationProvider;
            }
        }
    }
}
