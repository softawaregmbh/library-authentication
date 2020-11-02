using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using softaware.Authentication.Basic.AspNetCore.AuthorizationProvider;

namespace softaware.Authentication.Basic.AspNetCore.Test
{
    public class TestWebApplicationFactory : WebApplicationFactory<TestStartup>
    {
        private readonly IBasicAuthorizationProvider basicAuthorizationProvider;

        public TestWebApplicationFactory(IBasicAuthorizationProvider basicAuthorizationProvider)
        {
            this.basicAuthorizationProvider = basicAuthorizationProvider;
        }

        protected override IWebHostBuilder CreateWebHostBuilder()
        {
            return new WebHostBuilder().UseStartup<TestStartup>();
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureServices(services =>
            {
                services.AddTransient(_ => this.basicAuthorizationProvider);

                services.AddAuthentication(o =>
                {
                    o.DefaultScheme = BasicAuthenticationDefaults.AuthenticationScheme;
                })
                .AddBasicAuthentication();
            });
        }
    }
}
