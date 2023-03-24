using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace softaware.Authentication.Hmac.AspNetCore.Test
{
    internal class RemoveHashingMethodDelegatingHandler : DelegatingHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var hmacAuthHeaderValue = request.Headers.Authorization?.Parameter;
            if (hmacAuthHeaderValue != null)
            {
                var values = hmacAuthHeaderValue.Split(":").ToList();

                if (values.Count == 6) // Hmac header has HmacHashingAlgorithm and RequestBodyHashingAlgorithm paramemters set
                {
                    request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
                        request.Headers.Authorization.Scheme,
                        string.Join(":", values.Skip(2))); // remove first two parameters (= HmacHashingAlgorithm and RequestBodyHashingAlgorithm)
                }
            }

            return base.SendAsync(request, cancellationToken);
        }
    }
}
