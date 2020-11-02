using Microsoft.Extensions.Options;
using softaware.Authentication.Hmac.AuthorizationProvider;

namespace softaware.Authentication.Hmac.AspNetCore
{
    public class HmacAuthenticationPostConfigureOptions : IPostConfigureOptions<HmacAuthenticationSchemeOptions>
    {
        private readonly IHmacAuthorizationProvider hmacAuthorizationProvider;

        public HmacAuthenticationPostConfigureOptions(IHmacAuthorizationProvider hmacAuthorizationProvider = null)
        {
            this.hmacAuthorizationProvider = hmacAuthorizationProvider;
        }

        public void PostConfigure(string name, HmacAuthenticationSchemeOptions options)
        {
            if (this.hmacAuthorizationProvider != null)
            {
                options.AuthorizationProvider = this.hmacAuthorizationProvider;
            }
        }
    }
}
