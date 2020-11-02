using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using softaware.Authentication.Hmac.AuthorizationProvider;

namespace softaware.Authentication.Hmac.AspNetCore.Test
{
    public class TestWebApplicationFactoryWithDefaultAuthorizationProvider : WebApplicationFactory<TestStartup>
    {
        private readonly IDictionary<string, string> hmacAuthenticatedApps;

        public TestWebApplicationFactoryWithDefaultAuthorizationProvider(IDictionary<string, string> hmacAuthenticatedApps)
        {
            this.hmacAuthenticatedApps = hmacAuthenticatedApps ?? throw new ArgumentNullException(nameof(hmacAuthenticatedApps));
        }

        protected override IWebHostBuilder CreateWebHostBuilder()
        {
            return new WebHostBuilder().UseStartup<TestStartup>();
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureServices(services =>
            {
                services.AddTransient<IHmacAuthorizationProvider>(sp => new MemoryHmacAuthenticationProvider(this.hmacAuthenticatedApps));

                services.AddAuthentication(o =>
                {
                    o.DefaultScheme = HmacAuthenticationDefaults.AuthenticationScheme;
                })
                .AddHmacAuthentication();
            });
        }
    }
}
