using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using softaware.Authentication.SasToken.Generators;
using softaware.Authentication.SasToken.Validators;

namespace softaware.Authentication.SasToken.AspNetCore
{
    public static class SasTokenAuthenticationExtensions
    {
        /// <summary>
        /// Adds the SAS token authentication.
        /// An <see cref="SasToken.KeyProvider.IKeyProvider"/> must be registered in the dependency injection container.
        /// </summary>
        public static AuthenticationBuilder AddSasTokenAuthentication(this AuthenticationBuilder builder)
            => builder.AddSasTokenAuthentication(SasTokenAuthenticationDefaults.AuthenticationScheme, _ => { });

        /// <summary>
        /// Adds the SAS token authentication.
        /// An <see cref="SasToken.KeyProvider.IKeyProvider"/> must be registered in the dependency injection container.
        /// </summary>
        public static AuthenticationBuilder AddSasTokenAuthentication(this AuthenticationBuilder builder, Action<SasTokenAuthenticationSchemeOptions> configureOptions)
            => builder.AddSasTokenAuthentication(SasTokenAuthenticationDefaults.AuthenticationScheme, configureOptions);

        /// <summary>
        /// Adds the SAS token authentication.
        /// An <see cref="SasToken.KeyProvider.IKeyProvider"/> must be registered in the dependency injection container.
        /// </summary>
        public static AuthenticationBuilder AddSasTokenAuthentication(this AuthenticationBuilder builder, string authenticationScheme, Action<SasTokenAuthenticationSchemeOptions> configureOptions)
            => builder.AddSasTokenAuthentication(authenticationScheme, displayName: null, configureOptions);

        /// <summary>
        /// Adds the SAS token authentication.
        /// An <see cref="SasToken.KeyProvider.IKeyProvider"/> must be registered in the dependency injection container.
        /// </summary>
        public static AuthenticationBuilder AddSasTokenAuthentication(
            this AuthenticationBuilder builder,
            string authenticationScheme,
            string? displayName,
            Action<SasTokenAuthenticationSchemeOptions> configureOptions)
        {
            builder.Services.AddSasTokenAuthenticationServices();

            return builder.AddScheme<SasTokenAuthenticationSchemeOptions, SasTokenAuthenticationHandler>(authenticationScheme, displayName, configureOptions);
        }

        /// <summary>
        /// Adds the SAS token authentication services.
        /// An <see cref="SasToken.KeyProvider.IKeyProvider"/> must be registered in the dependency injection container.
        /// </summary>
        public static IServiceCollection AddSasTokenAuthenticationServices(this IServiceCollection services)
        {
            services.AddTransient<SasTokenUrlGenerator>();
            services.AddTransient<SasTokenSignatureGenerator>();
            services.AddTransient<SasTokenSignatureValidator>();

            return services;
        }
    }
}
