﻿using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using softaware.Authentication.SasToken.KeyProvider;

namespace softaware.Authentication.SasToken.AspNetCore.Test
{
    public class TestWebApplicationFactory(IKeyProvider keyProvider, string? nameIdentifierQueryParameter)
        : WebApplicationFactory<TestStartup>
    {
        private readonly IKeyProvider keyProvider = keyProvider;
        private readonly string? nameIdentifierQueryParameter = nameIdentifierQueryParameter;

        protected override IWebHostBuilder CreateWebHostBuilder()
        {
            return new WebHostBuilder().UseStartup<TestStartup>();
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureServices(services =>
            {
                services.AddTransient(_ => this.keyProvider);

                services.AddAuthentication(o =>
                {
                    o.DefaultScheme = SasTokenAuthenticationDefaults.AuthenticationScheme;
                })
                .AddSasTokenAuthentication(o =>
                {
                    o.NameIdentifierQueryParameter = nameIdentifierQueryParameter;
                });
            });
        }
    }
}
