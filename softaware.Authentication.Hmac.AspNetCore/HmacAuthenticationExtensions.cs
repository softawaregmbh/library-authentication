using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Authentication;

namespace softaware.Authentication.Hmac.AspNetCore
{
    public static class HmacAuthenticationExtensions
    {
        public static AuthenticationBuilder AddHmacAuthentication(
            this AuthenticationBuilder builder,
            string authenticationScheme,
            string displayName,
            Action<HmacAuthenticationSchemeOptions> configureOptions)
        {
            return builder.AddScheme<HmacAuthenticationSchemeOptions, HmacAuthenticationHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}
