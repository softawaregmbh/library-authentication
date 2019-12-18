using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using softaware.Authentication.Hmac.Client;
using Xunit;

namespace softaware.Authentication.Hmac.AspNetCore.Test
{
    public class MiddlewareTest
    {
        [Fact]
        public Task Request_Authorized()
        {
            return this.TestRequestAsync(
                new Dictionary<string, string>() { { "appId", "MNpx/353+rW+pqv8UbRTAtO1yoabl8/RFDAv/615u5w=" } },
                "appId",
                "MNpx/353+rW+pqv8UbRTAtO1yoabl8/RFDAv/615u5w=",
                HttpStatusCode.OK);
        }

        [Theory]
        [InlineData("appId", "YXJld3JzZHJkc2FhcndlZQ==")]
        [InlineData("wrongAppId", "MNpx/353+rW+pqv8UbRTAtO1yoabl8/RFDAv/615u5w=")]
        public Task Request_Unauthorized(string appId, string apiKey)
        {
            return this.TestRequestAsync(
                new Dictionary<string, string>() { { "appId", "MNpx/353+rW+pqv8UbRTAtO1yoabl8/RFDAv/615u5w=" } },
                appId,
                apiKey,
                HttpStatusCode.Unauthorized);
        }

        [Theory]
        [InlineData("appId", "MNpx/353+rW+sdf/RFDAv/615u5w=")]
        [InlineData("wrongAppId", "MNpx/353+rW+sdf/RFDAv/615u5w=")]
        public Task Request_ApiKeyBadFormat_ThrowsException(string appId, string apiKey)
        {
            return Assert.ThrowsAsync<ArgumentException>(() => this.TestRequestAsync(
                new Dictionary<string, string>() { { "appId", "MNpx/353+rW+pqv8UbRTAtO1yoabl8/RFDAv/615u5w=" } },
                appId,
                apiKey,
                HttpStatusCode.Unauthorized));
        }

        [Fact]
        public async Task Request_Authorized_UsernameAppIdSet()
        {
            var appId = "appId";

            var result = await this.TestRequestAsync(
                new Dictionary<string, string>() { { appId, "MNpx/353+rW+pqv8UbRTAtO1yoabl8/RFDAv/615u5w=" } },
                appId,
                "MNpx/353+rW+pqv8UbRTAtO1yoabl8/RFDAv/615u5w=",
                HttpStatusCode.OK,
                "api/test/name");

            var content = await result.Content.ReadAsStringAsync();

            Assert.Equal(appId, content);
        }

        [Fact]
        public async Task Request_Authorized_Claims()
        {
            var appId = "appId";

            var result = await this.TestRequestAsync(
                new Dictionary<string, string>() { { appId, "MNpx/353+rW+pqv8UbRTAtO1yoabl8/RFDAv/615u5w=" } },
                appId,
                "MNpx/353+rW+pqv8UbRTAtO1yoabl8/RFDAv/615u5w=",
                HttpStatusCode.OK,
                "api/test/claims");

            var contentAsString = await result.Content.ReadAsStringAsync();
            dynamic content = JArray.Parse(contentAsString);

            Assert.Equal(1, content.Count);
            Assert.Equal(ClaimTypes.NameIdentifier, content[0].name.Value);
            Assert.Equal(appId, content[0].value.Value);
        }

        private async Task<HttpResponseMessage> TestRequestAsync(
            IDictionary<string, string> authenticatedApps,
            string appId,
            string apiKey,
            HttpStatusCode expectedStatusCode,
            string endpoint = "api/test")
        {
            using (var client = this.GetHttpClient(
                authenticatedApps,
                appId,
                apiKey))
            {
                var response = await client.GetAsync(endpoint);
                Assert.True(response.StatusCode == expectedStatusCode);

                return response;
            }
        }

        private HttpClient GetHttpClient(IDictionary<string, string> hmacAuthenticatedApps, string appId, string apiKey)
        {
            var factory = new TestWebApplicationFactory(hmacAuthenticatedApps);
            return factory.CreateDefaultClient(new ApiKeyDelegatingHandler(appId, apiKey));
        }
    }
}
