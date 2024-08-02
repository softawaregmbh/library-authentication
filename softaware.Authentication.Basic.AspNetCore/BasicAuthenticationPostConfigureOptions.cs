using Microsoft.Extensions.Options;
using softaware.Authentication.Basic.AspNetCore.AuthorizationProvider;

namespace softaware.Authentication.Basic.AspNetCore;

public class BasicAuthenticationPostConfigureOptions(IBasicAuthorizationProvider basicAuthorizationProvider = null)
    : IPostConfigureOptions<BasicAuthenticationSchemeOptions>
{
    private readonly IBasicAuthorizationProvider basicAuthorizationProvider = basicAuthorizationProvider;

    public void PostConfigure(string name, BasicAuthenticationSchemeOptions options)
    {
        if (this.basicAuthorizationProvider != null)
        {
            options.AuthorizationProvider = this.basicAuthorizationProvider;
        }
    }
}
