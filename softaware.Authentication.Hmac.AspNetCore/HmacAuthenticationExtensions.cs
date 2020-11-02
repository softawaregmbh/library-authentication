using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace softaware.Authentication.Hmac.AspNetCore
{
    public static class HmacAuthenticationExtensions
    {
        public static AuthenticationBuilder AddHmacAuthentication(
            this AuthenticationBuilder builder)
        {
            return builder.AddHmacAuthentication(_ => { });
        }

        public static AuthenticationBuilder AddHmacAuthentication(
            this AuthenticationBuilder builder,
            Action<HmacAuthenticationSchemeOptions> configureOptions)
        {
            return builder.AddHmacAuthentication(
                HmacAuthenticationDefaults.AuthenticationScheme,
                HmacAuthenticationDefaults.AuthenticationType,
                configureOptions);
        }

        public static AuthenticationBuilder AddHmacAuthentication(
            this AuthenticationBuilder builder,
            string authenticationScheme,
            string displayName,
            Action<HmacAuthenticationSchemeOptions> configureOptions)
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<HmacAuthenticationSchemeOptions>, HmacAuthenticationPostConfigureOptions>());
            return builder.AddScheme<HmacAuthenticationSchemeOptions, HmacAuthenticationHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}
