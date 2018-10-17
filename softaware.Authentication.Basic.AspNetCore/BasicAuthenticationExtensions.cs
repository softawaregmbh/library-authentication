using System;
using Microsoft.AspNetCore.Authentication;
using softaware.Authentication.Hmac.AspNetCore;

namespace softaware.Authentication.Basic.AspNetCore
{
    public static class BasicAuthenticationExtensions
    {
        public static AuthenticationBuilder AddBasicAuthentication(
            this AuthenticationBuilder builder,
            string authenticationScheme,
            Action<BasicAuthenticationSchemeOptions> configureOptions)
        {
            return builder.AddScheme<BasicAuthenticationSchemeOptions, BasicAuthenticationHandler>(authenticationScheme, authenticationScheme, configureOptions);
        }

        public static AuthenticationBuilder AddBasicAuthentication(
            this AuthenticationBuilder builder,
            string authenticationScheme,
            string displayName,
            Action<BasicAuthenticationSchemeOptions> configureOptions)
        {
            return builder.AddScheme<BasicAuthenticationSchemeOptions, BasicAuthenticationHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}
