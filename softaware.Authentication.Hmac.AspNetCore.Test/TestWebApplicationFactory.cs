using System.Collections.Generic;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace softaware.Authentication.Hmac.AspNetCore.Test
{
    public class TestWebApplicationFactory : WebApplicationFactory<TestStartup>
    {
        private readonly IDictionary<string, string> hmacAuthenticatedApps;

        public TestWebApplicationFactory(IDictionary<string, string> hmacAuthenticatedApps)
        {
            this.hmacAuthenticatedApps = hmacAuthenticatedApps;
        }

        protected override IWebHostBuilder CreateWebHostBuilder()
        {
            return new WebHostBuilder().UseStartup<TestStartup>();
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureServices(services =>
            {
                services.AddAuthentication(o =>
                {
                    o.DefaultScheme = HmacAuthenticationDefaults.AuthenticationScheme;
                })
                .AddHmacAuthentication(
                    HmacAuthenticationDefaults.AuthenticationScheme,
                    HmacAuthenticationDefaults.AuthenticationType, 
                    o =>
                {
                    o.MaxRequestAgeInSeconds = HmacAuthenticationDefaults.MaxRequestAgeInSeconds;
                    o.HmacAuthenticatedApps = this.hmacAuthenticatedApps;
                });
            });
        }
    }
}
