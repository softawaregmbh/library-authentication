using System.Collections.Immutable;
using System.Globalization;
using Microsoft.Extensions.Primitives;
using softaware.Authentication.SasToken.Models;

namespace softaware.Authentication.SasToken.Generators
{
    public class SasTokenUrlGenerator(SasTokenSignatureGenerator sasTokenSignatureGenerator)
    {
        /// <param name="endpoint">The endpoint of the URI starting with a leading "/".</param>
        public Task<string> GenerateSasTokenQueryStringAsync(
            string endpoint,
            DateTime startTime,
            DateTime endTime,
            QueryParameterHandlingType queryParameterHandlingType,
            CancellationToken cancellationToken) => GenerateSasTokenQueryStringAsync(
                endpoint,
                ImmutableDictionary<string, StringValues>.Empty,
                startTime,
                endTime,
                queryParameterHandlingType,
                cancellationToken);

        /// <param name="endpoint">The endpoint of the URI starting with a leading "/".</param>
        public async Task<string> GenerateSasTokenQueryStringAsync(
            string endpoint,
            IDictionary<string, StringValues> queryParameters,
            DateTime startTime,
            DateTime endTime,
            QueryParameterHandlingType queryParameterHandlingType,
            CancellationToken cancellationToken)
        {
            var signature = await sasTokenSignatureGenerator.GenerateAsync(endpoint, startTime, endTime, queryParameterHandlingType, queryParameters, cancellationToken);

            return
                $"?sv={SasTokenVersion.Version1}&" +
                $"st={startTime.ToString("s", CultureInfo.InvariantCulture)}&" +
                $"se={endTime.ToString("s", CultureInfo.InvariantCulture)}&" +
                $"sq={QueryParameterHandlingTypeExtensions.GetQueryParameterValue(queryParameterHandlingType)}&" +
                $"sp={string.Join(",", queryParameters.Keys)}&" +
                $"sig={signature}";
        }

        /// <param name="baseUrl">The base url <strong>without</strong> trailing "/".</param>
        /// <param name="endpoint">The endpoint of the URI starting with a leading "/".</param>
        public Task<Uri> GenerateSasTokenUriAsync(
            string baseUrl,
            string endpoint,
            DateTime startTime,
            DateTime endTime,
            QueryParameterHandlingType queryParameterHandlingType,
            CancellationToken cancellationToken) => GenerateSasTokenUriAsync(
                baseUrl,
                endpoint,
                ImmutableDictionary<string, StringValues>.Empty,
                startTime,
                endTime,
                queryParameterHandlingType,
                cancellationToken);

        /// <param name="baseUrl">The base url <strong>without</strong> trailing "/".</param>
        /// <param name="endpoint">The endpoint of the URI starting with a leading "/".</param>
        public async Task<Uri> GenerateSasTokenUriAsync(
            string baseUrl,
            string endpoint,
            IDictionary<string, StringValues> queryParameters,
            DateTime startTime,
            DateTime endTime,
            QueryParameterHandlingType queryParameterHandlingType,
            CancellationToken cancellationToken) =>
            new($"{baseUrl}{endpoint}{await GenerateSasTokenQueryStringAsync(endpoint, queryParameters, startTime, endTime, queryParameterHandlingType, cancellationToken)}");
    }
}
