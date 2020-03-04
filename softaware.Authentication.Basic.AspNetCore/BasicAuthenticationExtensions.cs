using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using softaware.Authentication.Hmac.AspNetCore;

namespace softaware.Authentication.Basic.AspNetCore
{
    public static class BasicAuthenticationExtensions
    {
        public static AuthenticationBuilder AddBasicAuthentication(this AuthenticationBuilder builder)
            => builder.AddBasicAuthentication(BasicAuthenticationDefaults.AuthenticationScheme, _ => { });

        public static AuthenticationBuilder AddBasicAuthentication(this AuthenticationBuilder builder, Action<BasicAuthenticationSchemeOptions> configureOptions)
            => builder.AddBasicAuthentication(BasicAuthenticationDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddBasicAuthentication(this AuthenticationBuilder builder, string authenticationScheme, Action<BasicAuthenticationSchemeOptions> configureOptions)
            => builder.AddBasicAuthentication(authenticationScheme, displayName: null, configureOptions);

        public static AuthenticationBuilder AddBasicAuthentication(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<BasicAuthenticationSchemeOptions> configureOptions)
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<BasicAuthenticationSchemeOptions>, BasicAuthenticationPostConfigureOptions>());
            return builder.AddScheme<BasicAuthenticationSchemeOptions, BasicAuthenticationHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}
