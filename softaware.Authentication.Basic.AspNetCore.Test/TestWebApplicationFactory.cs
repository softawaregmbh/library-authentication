using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using softaware.Authentication.Basic.AspNetCore.AuthorizationProvider;

namespace softaware.Authentication.Basic.AspNetCore.Test
{
    public class TestWebApplicationFactory : WebApplicationFactory<TestStartup>
    {
        private readonly IBasicAuthorizationProvider basicAuthorizationProvider;
        private readonly BasicAuthenticationSchemeOptions basicAuthenticationSchemeOptions;

        public TestWebApplicationFactory(IBasicAuthorizationProvider basicAuthorizationProvider, BasicAuthenticationSchemeOptions basicAuthenticationSchemeOptions = null)
        {
            this.basicAuthorizationProvider = basicAuthorizationProvider;
            this.basicAuthenticationSchemeOptions = basicAuthenticationSchemeOptions;
        }

        protected override IWebHostBuilder CreateWebHostBuilder()
        {
            return new WebHostBuilder().UseStartup<TestStartup>();
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureServices(services =>
            {
                services.AddTransient((_) => this.basicAuthorizationProvider);

                services.AddAuthentication(o =>
                {
                    o.DefaultScheme = BasicAuthenticationDefaults.AuthenticationScheme;
                })
                .AddBasicAuthentication(BasicAuthenticationDefaults.AuthenticationScheme, o =>
                {
                    o.AuthorizationProvider = this.basicAuthorizationProvider;
                    o.AddPasswordAsClaim = basicAuthenticationSchemeOptions?.AddPasswordAsClaim ?? false;
                    o.AddTokenAsClaim = basicAuthenticationSchemeOptions?.AddTokenAsClaim ?? false;
                });
            });
        }
    }
}
