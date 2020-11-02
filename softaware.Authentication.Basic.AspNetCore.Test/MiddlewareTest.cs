using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using softaware.Authentication.Basic.AspNetCore.AuthorizationProvider;
using softaware.Authentication.Basic.Client;
using Xunit;

namespace softaware.Authentication.Basic.AspNetCore.Test
{
    public class MiddlewareTest
    {
        [Fact]
        public Task Request_MemoryProvider_Authorized()
        {
            return this.TestRequestAsync(
                new MemoryBasicAuthenticationProvider(new Dictionary<string, string>() { { "username", "password" } }),
                "username",
                "password",
                HttpStatusCode.OK);
        }

        [Theory]
        [InlineData("username", "wrongPassword")]
        [InlineData("wrongUsername", "password")]
        [InlineData("wrongUsername", "wrongPassword")]
        public Task Request_MemoryProvider_Unauthorized(string username, string password)
        {
            return this.TestRequestAsync(
                new MemoryBasicAuthenticationProvider(new Dictionary<string, string>() { { "username", "password" } }),
                username,
                password,
                HttpStatusCode.Unauthorized);
        }

        [Fact]
        public Task Request_SecureMemoryProvider_Authorized()
        {
            return this.TestRequestAsync(
                new SecureMemoryBasicAuthenticationProvider(new Dictionary<string, string>() { { "username", "password" } }),
                "username",
                "password",
                HttpStatusCode.OK);
        }

        [Theory]
        [InlineData("username", "wrongPassword")]
        [InlineData("wrongUsername", "password")]
        [InlineData("wrongUsername", "wrongPassword")]
        public Task Request_SecureMemoryProvider_Unauthorized(string username, string password)
        {
            return this.TestRequestAsync(
                new SecureMemoryBasicAuthenticationProvider(new Dictionary<string, string>() { { "username", "password" } }),
                username,
                password,
                HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task Request_SecureMemoryProvider_Authorized_UsernameSet()
        {
            var username = "username";

            var result = await this.TestRequestAsync(
                new SecureMemoryBasicAuthenticationProvider(new Dictionary<string, string>() { { username, "password" } }),
                username,
                "password",
                HttpStatusCode.OK,
                "api/test/name");

            var content = await result.Content.ReadAsStringAsync();

            Assert.Equal(username, content);
        }

        [Fact]
        public async Task Request_SecureMemoryProvider_Authorized_Claims()
        {
            var username = "username";

            var result = await this.TestRequestAsync(
                new SecureMemoryBasicAuthenticationProvider(new Dictionary<string, string>() { { username, "password" } }),
                username,
                "password",
                HttpStatusCode.OK,
                "api/test/claims");

            var contentAsString = await result.Content.ReadAsStringAsync();
            dynamic content = JArray.Parse(contentAsString);

            Assert.Equal(1, content.Count);
            Assert.Equal(ClaimTypes.NameIdentifier, content[0].name.Value);
            Assert.Equal(username, content[0].value.Value);
        }

        [Fact]
        public async Task Request_SecureMemoryProvider_Authorized_Claims_With_Password()
        {
            var username = "username";
            var password = "password";

            var result = await this.TestRequestAsync(
                new SecureMemoryBasicAuthenticationProvider(new Dictionary<string, string>() { { username, password } }),
                username,
                password,
                HttpStatusCode.OK,
                "api/test/claims",
                new BasicAuthenticationSchemeOptions()
                {
                    AddPasswordAsClaim = true
                });

            var contentAsString = await result.Content.ReadAsStringAsync();
            dynamic content = JArray.Parse(contentAsString);

            Assert.Equal(2, content.Count);
            Assert.Equal(BasicAuthenticationDefaults.PasswordClaimType, content[1].name.Value);
            Assert.Equal(password, content[1].value.Value);
        }

        [Fact]
        public async Task Request_SecureMemoryProvider_Authorized_Claims_With_Token()
        {
            var username = "username";
            var password = "password";

            var result = await this.TestRequestAsync(
                new SecureMemoryBasicAuthenticationProvider(new Dictionary<string, string>() { { username, password } }),
                username,
                password,
                HttpStatusCode.OK,
                "api/test/claims",
                new BasicAuthenticationSchemeOptions()
                {
                    AddTokenAsClaim = true
                });

            var contentAsString = await result.Content.ReadAsStringAsync();
            dynamic content = JArray.Parse(contentAsString);

            Assert.Equal(2, content.Count);
            Assert.Equal(BasicAuthenticationDefaults.TokenClaimType, content[1].name.Value);
            Assert.Equal(Convert.ToBase64String(Encoding.ASCII.GetBytes(string.Format("{0}:{1}", username, password))), content[1].value.Value);
        }

        private async Task<HttpResponseMessage> TestRequestAsync(
            IBasicAuthorizationProvider basicAuthorizationProvider,
            string username,
            string password,
            HttpStatusCode expectedStatusCode,
            string endpoint = "api/test",
            BasicAuthenticationSchemeOptions basicAuthenticationSchemeOptions = null)
        {
            using (var client = this.GetHttpClient(
                basicAuthorizationProvider,
                username,
                password,
                basicAuthenticationSchemeOptions))
            {
                var response = await client.GetAsync(endpoint);
                Assert.True(response.StatusCode == expectedStatusCode);

                return response;
            }
        }

        private HttpClient GetHttpClient(
            IBasicAuthorizationProvider basicAuthorizationProvider, string username, string password, BasicAuthenticationSchemeOptions basicAuthenticationSchemeOptions = null)
        {
            var factory = new TestWebApplicationFactory(basicAuthorizationProvider, basicAuthenticationSchemeOptions);
            return factory.CreateDefaultClient(new BasicAuthenticationDelegatingHandler(username, password));
        }
    }
}
