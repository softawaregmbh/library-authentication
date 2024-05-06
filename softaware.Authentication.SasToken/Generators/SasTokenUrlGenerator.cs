using System.Globalization;
using softaware.Authentication.SasToken.Models;

namespace softaware.Authentication.SasToken.Generators
{
    public class SasTokenUrlGenerator(SasTokenSignatureGenerator sasTokenSignatureGenerator)
    {
        public async Task<string> GenerateSasTokenQueryStringAsync(
            string endpoint,
            string[] queryParameters,
            DateTime startTime,
            DateTime endTime,
            SasTokenType sasTokenType,
            CancellationToken cancellationToken)
        {
            var signature = await sasTokenSignatureGenerator.GenerateAsync(startTime, endTime, sasTokenType, endpoint, queryParameters, cancellationToken);

            return
                $"?sv={SasTokenVersion.Version1}&" +
                $"st={startTime.ToString("s", CultureInfo.InvariantCulture)}&" +
                $"se={endTime.ToString("s", CultureInfo.InvariantCulture)}&" +
                $"stt={SasTokenTypeExtensions.GetQueryParameterName(sasTokenType)}&" +
                $"sig={signature}";
        }

        public async Task<Uri> GenerateSasTokenUriAsync(
            string baseUrl,
            string endpoint,
            string[] queryParameters,
            DateTime startTime,
            DateTime endTime,
            SasTokenType sasTokenType,
            CancellationToken cancellationToken) =>
            new($"{baseUrl}{endpoint}{await GenerateSasTokenQueryStringAsync(endpoint, queryParameters, startTime, endTime, sasTokenType, cancellationToken)}");
    }
}
