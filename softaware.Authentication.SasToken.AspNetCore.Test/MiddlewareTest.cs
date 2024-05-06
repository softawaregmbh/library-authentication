using System.Net;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using softaware.Authentication.SasToken.AspNetCore.Test;
using softaware.Authentication.SasToken.Generators;
using softaware.Authentication.SasToken.KeyProvider;
using softaware.Authentication.SasToken.Models;

namespace softaware.Authentication.Basic.AspNetCore.Test
{
    public class MiddlewareTest
    {
        private TestWebApplicationFactory webAppFactory;
        private HttpClient httpClient;
        private SasTokenUrlGenerator urlGenerator;

        public MiddlewareTest()
        {
            var keyProvider = new MemoryKeyProvider("key");
            this.webAppFactory = new TestWebApplicationFactory(keyProvider);

            this.urlGenerator = this.webAppFactory.Services.GetRequiredService<SasTokenUrlGenerator>();
            this.httpClient = this.webAppFactory.CreateDefaultClient();
        }

        [Fact]
        public async Task Request_Authorized()
        {
            var relativeUrl = "api/test" + await urlGenerator.GenerateSasTokenQueryStringAsync("/api/test", [], DateTime.UtcNow, DateTime.UtcNow.AddMinutes(5), SasToken.Models.SasTokenType.IgnoreAdditionalQueryParameters, CancellationToken.None);

            await this.TestRequestAsync(
                relativeUrl,
                HttpStatusCode.NoContent);
        }

        [Fact]
        public async Task Request_EndDateReached_NotAuthorized()
        {
            var relativeUrl = "api/test" + await urlGenerator.GenerateSasTokenQueryStringAsync("/api/test", [], DateTime.UtcNow.AddMinutes(-10), DateTime.UtcNow.AddMinutes(-5), SasToken.Models.SasTokenType.IgnoreAdditionalQueryParameters, CancellationToken.None);

            await this.TestRequestAsync(
                relativeUrl,
                HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task Request_InvalidSignature_NotAuthorized()
        {
            var relativeUrl = "api/test" + await urlGenerator.GenerateSasTokenQueryStringAsync("/api/test", [], DateTime.UtcNow, DateTime.UtcNow.AddMinutes(5), SasToken.Models.SasTokenType.IgnoreAdditionalQueryParameters, CancellationToken.None);
            var queryDict = QueryHelpers.ParseQuery(new Uri("https://" + relativeUrl).Query);
            queryDict["sig"] = queryDict["sig"] + "invalid";

            relativeUrl = QueryHelpers.AddQueryString("api/test", queryDict);

            await this.TestRequestAsync(
                relativeUrl,
                HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task Request_AdditionalParameterInSignature_NotProvidedInUrl_NotAuthorized()
        {
            var relativeUrl = "api/test" +
                await urlGenerator.GenerateSasTokenQueryStringAsync("/api/test", ["parameter=1"], DateTime.UtcNow, DateTime.UtcNow.AddMinutes(5), SasToken.Models.SasTokenType.ConsiderAllQueryParameters, CancellationToken.None) +
                "&missing-parameter=1";

            await this.TestRequestAsync(
                relativeUrl,
                HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task Request_AdditionalParameterInUrl_NotProvidedInSignature_IgnoreAdditionalQueryParameters_Authorized()
        {
            var relativeUrl = "api/test" +
                await urlGenerator.GenerateSasTokenQueryStringAsync("/api/test", [], DateTime.UtcNow, DateTime.UtcNow.AddMinutes(5), SasTokenType.IgnoreAdditionalQueryParameters, CancellationToken.None) +
                "&parameter=1";

            await this.TestRequestAsync(
                relativeUrl,
                HttpStatusCode.OK);
        }

        [Fact]
        public async Task Request_AdditionalParameterInUrl_NotProvidedInSignature_ConsiderAllQueryParameters_NotAuthorized()
        {
            var relativeUrl = "api/test" +
                await urlGenerator.GenerateSasTokenQueryStringAsync("/api/test", [], DateTime.UtcNow, DateTime.UtcNow.AddMinutes(5), SasTokenType.ConsiderAllQueryParameters, CancellationToken.None) +
                "&parameter=1";

            await this.TestRequestAsync(
                relativeUrl,
                HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task Request_AdditionalParameter_NotIgnored_Authorized()
        {
            var relativeUrl = "api/test" +
                await urlGenerator.GenerateSasTokenQueryStringAsync("/api/test", ["parameter=1"], DateTime.UtcNow, DateTime.UtcNow.AddMinutes(5), SasToken.Models.SasTokenType.ConsiderAllQueryParameters, CancellationToken.None) +
                "&parameter=1";

            var response = await this.TestRequestAsync(
                relativeUrl,
                HttpStatusCode.OK);

            var content = await response.Content.ReadAsStringAsync();
            Assert.Equal("1", content);
        }

        private async Task<HttpResponseMessage> TestRequestAsync(
            string relativeUrl,
            HttpStatusCode expectedStatusCode)
        {
            var response = await this.httpClient.GetAsync(relativeUrl);
            Assert.Equal(expectedStatusCode, response.StatusCode);

            return response;
        }
    }
}
