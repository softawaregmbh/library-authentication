using System;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace softaware.Authentication.Hmac.AspNetCore.Test
{
    public class TestWebApplicationFactory(Action<HmacAuthenticationSchemeOptions> configureOptions)
        : WebApplicationFactory<TestStartup>
    {
        private readonly Action<HmacAuthenticationSchemeOptions> configureOptions = configureOptions;

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
                    this.configureOptions);
            });
        }
    }
}
