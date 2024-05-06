using System.Security.Cryptography;
using System.Text;
using softaware.Authentication.SasToken.KeyProvider;
using softaware.Authentication.SasToken.Models;

namespace softaware.Authentication.SasToken.Generators
{
    public class SasTokenSignatureGenerator(IKeyProvider keyProvider)
    {
        public Task<string> GenerateAsync(
            DateTime startTime,
            DateTime endTime,
            SasTokenType sasTokenType,
            string endpoint,
            string[] queryParameters,
            CancellationToken cancellationToken)
            => GenerateAsync(startTime, endTime, sasTokenType, SasTokenVersion.Version1, endpoint, queryParameters, cancellationToken);

        public async Task<string> GenerateAsync(
            DateTime startTime,
            DateTime endTime,
            SasTokenType sasTokenType,
            int sasTokenVersion,
            string endpoint,
            string[] queryParameters,
            CancellationToken cancellationToken)
        {
            var stringToSign =
                $"rn{startTime.ToString("s", System.Globalization.CultureInfo.InvariantCulture)}" +
                $"/n{endTime.ToString("s", System.Globalization.CultureInfo.InvariantCulture)}" +
                $"/{sasTokenType}" +
                $"/{sasTokenVersion}" +
                $"/{endpoint}";

            if (queryParameters != null)
            {
                stringToSign += $"/{string.Join("/", queryParameters)}/n";
            }

            var key = await keyProvider.GetKeyAsync(cancellationToken);
            using var hmacsha256 = new HMACSHA256(Encoding.UTF8.GetBytes(key));
            var hash = hmacsha256.ComputeHash(Encoding.UTF8.GetBytes(stringToSign));
            return Convert.ToBase64String(hash);
        }
    }
}
