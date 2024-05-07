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
            QueryParameterHandlingType queryParameterHandlingType = QueryParameterHandlingType.DenyAdditionalQueryParameters,
            CancellationToken cancellationToken = default) => GenerateSasTokenQueryStringAsync(
                endpoint,
                ImmutableDictionary<string, StringValues>.Empty,
                startTime,
                endTime,
                queryParameterHandlingType,
                appendQueryParameters: false,
                cancellationToken);

        /// <param name="endpoint">The endpoint of the URI starting with a leading "/".</param>
        /// <param name="appendQueryParameters"><see langword="true"/>, if the provided query parameters should be appended to the query string.</param>
        public async Task<string> GenerateSasTokenQueryStringAsync(
            string endpoint,
            IDictionary<string, StringValues> queryParameters,
            DateTime startTime,
            DateTime endTime,
            QueryParameterHandlingType queryParameterHandlingType = QueryParameterHandlingType.DenyAdditionalQueryParameters,
            bool appendQueryParameters = true,
            CancellationToken cancellationToken = default)
        {
            var signature = await sasTokenSignatureGenerator.GenerateAsync(endpoint, startTime, endTime, queryParameterHandlingType, queryParameters, cancellationToken);

            var sasQueryString =
                $"?sv={SasTokenVersion.Version1}&" +
                $"st={startTime.ToString("s", CultureInfo.InvariantCulture)}&" +
                $"se={endTime.ToString("s", CultureInfo.InvariantCulture)}&" +
                $"sq={QueryParameterHandlingTypeExtensions.GetQueryParameterValue(queryParameterHandlingType)}&";

            if (queryParameterHandlingType == QueryParameterHandlingType.AllowAdditionalQueryParameters)
            {
                // The known query parameters are only needed if we allow additional query parameters to be appended so that we know
                // which query parameters need to be considered when calculating the signature.
                sasQueryString += $"sp={string.Join(",", queryParameters.Keys)}&";
            }

            sasQueryString += $"sig={signature}";

            if (appendQueryParameters && queryParameters.Any())
            {
                var queryParametersString = string.Join("&", queryParameters.Select(q => $"{q.Key}={q.Value}"));
                sasQueryString += $"&{queryParametersString}";
            }

            return sasQueryString;
        }

        /// <param name="baseUrl">The base url <strong>without</strong> trailing "/".</param>
        /// <param name="endpoint">The endpoint of the URI starting with a leading "/".</param>
        public Task<Uri> GenerateSasTokenUriAsync(
            string baseUrl,
            string endpoint,
            DateTime startTime,
            DateTime endTime,
            QueryParameterHandlingType queryParameterHandlingType = QueryParameterHandlingType.DenyAdditionalQueryParameters,
            CancellationToken cancellationToken = default) => GenerateSasTokenUriAsync(
                baseUrl,
                endpoint,
                ImmutableDictionary<string, StringValues>.Empty,
                startTime,
                endTime,
                queryParameterHandlingType,
                appendQueryParameters: false,
                cancellationToken);

        /// <param name="baseUrl">The base url <strong>without</strong> trailing "/".</param>
        /// <param name="endpoint">The endpoint of the URI starting with a leading "/".</param>
        /// <param name="appendQueryParameters"><see langword="true"/>, if the provided query parameters should be appended to the query string.</param>
        public async Task<Uri> GenerateSasTokenUriAsync(
            string baseUrl,
            string endpoint,
            IDictionary<string, StringValues> queryParameters,
            DateTime startTime,
            DateTime endTime,
            QueryParameterHandlingType queryParameterHandlingType = QueryParameterHandlingType.DenyAdditionalQueryParameters,
            bool appendQueryParameters = true,
            CancellationToken cancellationToken = default) =>
            new($"{baseUrl}{endpoint}{await GenerateSasTokenQueryStringAsync(endpoint, queryParameters, startTime, endTime, queryParameterHandlingType, appendQueryParameters, cancellationToken)}");
    }
}
