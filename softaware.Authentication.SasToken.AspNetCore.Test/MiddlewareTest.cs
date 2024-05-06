using System.Net;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;
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
            var relativeUrl = "api/test" + await urlGenerator.GenerateSasTokenQueryStringAsync("/api/test", DateTime.UtcNow, DateTime.UtcNow.AddMinutes(5), QueryParameterHandlingType.DenyAdditionalQueryParameters, CancellationToken.None);

            await this.TestRequestAsync(
                relativeUrl,
                HttpStatusCode.NoContent);
        }

        [Fact]
        public async Task Request_EndDateReached_NotAuthorized()
        {
            var relativeUrl = "api/test" + await urlGenerator.GenerateSasTokenQueryStringAsync("/api/test", DateTime.UtcNow.AddMinutes(-10), DateTime.UtcNow.AddMinutes(-5), QueryParameterHandlingType.DenyAdditionalQueryParameters, CancellationToken.None);

            await this.TestRequestAsync(
                relativeUrl,
                HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task Request_InvalidSignature_NotAuthorized()
        {
            var relativeUrl = "api/test" + await urlGenerator.GenerateSasTokenQueryStringAsync("/api/test", DateTime.UtcNow, DateTime.UtcNow.AddMinutes(5), QueryParameterHandlingType.DenyAdditionalQueryParameters, CancellationToken.None);
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
                await urlGenerator.GenerateSasTokenQueryStringAsync("/api/test", new Dictionary<string, StringValues> { ["parameter"] = new StringValues("1") }, DateTime.UtcNow, DateTime.UtcNow.AddMinutes(5), QueryParameterHandlingType.DenyAdditionalQueryParameters, CancellationToken.None);

            await this.TestRequestAsync(
                relativeUrl,
                HttpStatusCode.Unauthorized);
        }

        [Theory]
        [InlineData("1", "1", HttpStatusCode.OK)]
        [InlineData("1", "2", HttpStatusCode.Unauthorized)]
        [InlineData("2", "1", HttpStatusCode.Unauthorized)]
        public async Task Request_AdditionalParameterInUrl_ProvidedInSignature(string parameterValueInSignature, string parameterValueInUrl, HttpStatusCode expectedStatusCode)
        {
            var relativeUrl = "api/test" +
                await urlGenerator.GenerateSasTokenQueryStringAsync("/api/test", new Dictionary<string, StringValues> { ["parameter"] = new StringValues(parameterValueInSignature) }, DateTime.UtcNow, DateTime.UtcNow.AddMinutes(5), QueryParameterHandlingType.DenyAdditionalQueryParameters, CancellationToken.None) +
                $"&parameter={parameterValueInUrl}";

            await this.TestRequestAsync(
                relativeUrl,
                expectedStatusCode);
        }

        [Theory]
        [InlineData(QueryParameterHandlingType.DenyAdditionalQueryParameters, HttpStatusCode.Unauthorized)]
        [InlineData(QueryParameterHandlingType.AllowAdditionalQueryParameters, HttpStatusCode.NoContent)]
        public async Task Request_AdditionalParameterInUrl_NotProvidedInSignature(QueryParameterHandlingType queryParameterHandlingType, HttpStatusCode expectedStatusCode)
        {
            var relativeUrl = "api/test" +
                await urlGenerator.GenerateSasTokenQueryStringAsync("/api/test", new Dictionary<string, StringValues> { ["parameter1"] = new StringValues("1") }, DateTime.UtcNow, DateTime.UtcNow.AddMinutes(5), queryParameterHandlingType, CancellationToken.None) +
                "&parameter1=1&parameter2=2";

            await this.TestRequestAsync(
                relativeUrl,
                expectedStatusCode);
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
