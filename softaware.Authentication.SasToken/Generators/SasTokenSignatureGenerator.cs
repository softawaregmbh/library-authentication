using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Primitives;
using softaware.Authentication.SasToken.KeyProvider;
using softaware.Authentication.SasToken.Models;

namespace softaware.Authentication.SasToken.Generators
{
    public class SasTokenSignatureGenerator(IKeyProvider keyProvider)
    {
        /// <param name="endpoint">The endpoint of the URI starting with a leading "/".</param>
        public Task<string> GenerateAsync(
            string endpoint,
            DateTime startTime,
            DateTime endTime,
            QueryParameterHandlingType queryParameterHandlingType,
            IDictionary<string, StringValues> queryParameters,
            CancellationToken cancellationToken)
            => GenerateAsync(endpoint, startTime, endTime, queryParameterHandlingType, queryParameters, SasTokenVersion.Version1, cancellationToken);

        /// <param name="endpoint">The endpoint of the URI starting with a leading "/".</param>
        public async Task<string> GenerateAsync(
            string endpoint,
            DateTime startTime,
            DateTime endTime,
            QueryParameterHandlingType queryParameterHandlingType,
            IDictionary<string, StringValues> queryParameters,
            int sasTokenVersion,
            CancellationToken cancellationToken)
        {
            var stringToSign =
                $"rn{startTime.ToString("s", System.Globalization.CultureInfo.InvariantCulture)}" +
                $"/n{endTime.ToString("s", System.Globalization.CultureInfo.InvariantCulture)}" +
                $"/{queryParameterHandlingType}" +
                $"/{sasTokenVersion}" +
                $"/{endpoint}";

            if (queryParameters != null)
            {
                stringToSign += $"/{string.Join("/", queryParameters.Select(q => $"{q.Key}={q.Value}"))}/n";
            }

            var key = await keyProvider.GetKeyAsync(cancellationToken);
            using var hmacsha256 = new HMACSHA256(Encoding.UTF8.GetBytes(key));
            var hash = hmacsha256.ComputeHash(Encoding.UTF8.GetBytes(stringToSign));
            return Convert.ToBase64String(hash);
        }
    }
}
