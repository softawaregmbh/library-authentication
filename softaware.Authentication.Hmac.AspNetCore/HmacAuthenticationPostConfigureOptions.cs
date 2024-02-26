using Microsoft.Extensions.Options;
using softaware.Authentication.Hmac.AuthorizationProvider;

namespace softaware.Authentication.Hmac.AspNetCore
{
    public class HmacAuthenticationPostConfigureOptions(IHmacAuthorizationProvider hmacAuthorizationProvider = null)
        : IPostConfigureOptions<HmacAuthenticationSchemeOptions>
    {
        private readonly IHmacAuthorizationProvider hmacAuthorizationProvider = hmacAuthorizationProvider;

        public void PostConfigure(string name, HmacAuthenticationSchemeOptions options)
        {
            if (this.hmacAuthorizationProvider != null)
            {
                options.AuthorizationProvider = this.hmacAuthorizationProvider;
            }
        }
    }
}
