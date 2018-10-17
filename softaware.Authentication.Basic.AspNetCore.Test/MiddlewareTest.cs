using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using softaware.Authentication.Basic.AspNetCore.AuthorizationProvider;
using Xunit;

namespace softaware.Authentication.Basic.AspNetCore.Test
{
    public class MiddlewareTest
    {
        [Fact]
        public async Task Request_MemoryProvider_Authorized()
        {
            var username = "username";
            var password = "password";

            using (var client = this.GetHttpClient(new MemoryBasicAuthenticationProvider(new Dictionary<string, string>() { { "username", "password" } })))
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                    "Basic",
                    Convert.ToBase64String(Encoding.ASCII.GetBytes(string.Format("{0}:{1}", username, password))));

                var response = await client.GetAsync("api/test");
                Assert.True(response.StatusCode == System.Net.HttpStatusCode.OK);
            }
        }

        [Theory]
        [InlineData("username", "wrongPassword")]
        [InlineData("wrongUsername", "password")]
        [InlineData("wrongUsername", "wrongPassword")]
        public async Task Request_MemoryProvider_Unauthorized(string username, string password)
        {
            using (var client = this.GetHttpClient(new MemoryBasicAuthenticationProvider(new Dictionary<string, string>() { { "username", "password" } })))
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                    "Basic",
                    Convert.ToBase64String(Encoding.ASCII.GetBytes(string.Format("{0}:{1}", username, password))));

                var response = await client.GetAsync("api/test");
                Assert.True(response.StatusCode == System.Net.HttpStatusCode.Unauthorized);
            }
        }

        [Fact]
        public async Task Request_SecureMemoryProvider_Authorized()
        {
            var username = "username";
            var password = "password";

            using (var client = this.GetHttpClient(new SecureMemoryBasicAuthenticationProvider(new Dictionary<string, string>() { { "username", "password" } })))
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                    "Basic",
                    Convert.ToBase64String(Encoding.ASCII.GetBytes(string.Format("{0}:{1}", username, password))));

                var response = await client.GetAsync("api/test");
                Assert.True(response.StatusCode == System.Net.HttpStatusCode.OK);
            }
        }

        [Theory]
        [InlineData("username", "wrongPassword")]
        [InlineData("wrongUsername", "password")]
        [InlineData("wrongUsername", "wrongPassword")]
        public async Task Request_SecureMemoryProvider_Unauthorized(string username, string password)
        {
            using (var client = this.GetHttpClient(new SecureMemoryBasicAuthenticationProvider(new Dictionary<string, string>() { { "username", "password" } })))
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                    "Basic",
                    Convert.ToBase64String(Encoding.ASCII.GetBytes(string.Format("{0}:{1}", username, password))));

                var response = await client.GetAsync("api/test");
                Assert.True(response.StatusCode == System.Net.HttpStatusCode.Unauthorized);
            }
        }

        private HttpClient GetHttpClient(IBasicAuthorizationProvider basicAuthorizationProvider)
        {
            var testServer = new TestServer(new WebHostBuilder()
                .ConfigureServices(services =>
            {
                services.AddAuthentication(o =>
                {
                    o.DefaultScheme = BasicAuthenticationDefaults.AuthenticationScheme;
                })
                .AddBasicAuthentication(BasicAuthenticationDefaults.AuthenticationScheme, o =>
                {
                    o.AuthorizationProvider = basicAuthorizationProvider;
                });
            })
            .UseStartup<TestStartup>());
            return testServer.CreateClient();
        }
    }
}
