using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace softaware.Authentication.Hmac.Client
{
    public class ApiKeyDelegatingHandler : DelegatingHandler
    {
        private readonly string appId;
        private readonly string apiKey;
        private readonly HmacHashingMethod hmacHashingMethod;
        private readonly RequestBodyHashingMethod requestBodyHashingMethod;

        public ApiKeyDelegatingHandler(
            string appId,
            string apiKey,
            HmacHashingMethod hmacHashingMethod = HmacHashingMethod.HMACSHA256,
            RequestBodyHashingMethod requestBodyHashingMethod = RequestBodyHashingMethod.SHA256)
        {
            this.appId = appId ?? throw new ArgumentNullException(nameof(appId));
            this.apiKey = apiKey ?? throw new ArgumentNullException(nameof(apiKey));
            this.hmacHashingMethod = hmacHashingMethod;
            this.requestBodyHashingMethod = requestBodyHashingMethod;

            this.EnsureValidApiKey();
        }

        public ApiKeyDelegatingHandler(
            HttpMessageHandler innerHandler,
            string appId,
            string apiKey,
            HmacHashingMethod hmacHashingMethod = HmacHashingMethod.HMACSHA256,
            RequestBodyHashingMethod requestBodyHashingMethod = RequestBodyHashingMethod.SHA256)
            : base(innerHandler)
        {
            this.appId = appId ?? throw new ArgumentNullException(nameof(appId));
            this.apiKey = apiKey ?? throw new ArgumentNullException(nameof(apiKey));
            this.hmacHashingMethod = hmacHashingMethod;
            this.requestBodyHashingMethod = requestBodyHashingMethod;

            this.EnsureValidApiKey();
        }

        private void EnsureValidApiKey()
        {
            try
            {
                Convert.FromBase64String(this.apiKey);
            }
            catch (FormatException)
            {
                throw new ArgumentException($"{nameof(apiKey)} must be a valid base64 string.");
            }
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var requestContentBase64String = string.Empty;

            var requestUri = WebUtility.UrlEncode(request.RequestUri.AbsoluteUri.ToLower());

            var requestHttpMethod = request.Method.Method;

            // UNIX time
            var requestTimeStamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            // create random nonce for each request
            var nonce = Guid.NewGuid().ToString("N");

            // Checking if the request contains body, usually will be null wiht HTTP GET and DELETE
            if (request.Content != null)
            {
                var content = await request.Content.ReadAsByteArrayAsync();
                using (var hashAlgorithm = this.requestBodyHashingMethod.CreateHashAlgorithm())
                {
                    // Hashing the request body, any change in request body will result in different hash, we'll incure message integrity
                    var requestContentHash = hashAlgorithm.ComputeHash(content);
                    requestContentBase64String = Convert.ToBase64String(requestContentHash);
                }
            }

            // Creating the raw signature string
            var signatureRawData = $"{this.appId}{requestHttpMethod}{requestUri}{requestTimeStamp}{nonce}{requestContentBase64String}";

            var apiKeyBytes = Convert.FromBase64String(this.apiKey);
            var signature = Encoding.UTF8.GetBytes(signatureRawData);

            using (var hmac = this.hmacHashingMethod.CreateHmac(apiKeyBytes))
            {
                var signatureBytes = hmac.ComputeHash(signature);
                var requestSignatureBase64String = Convert.ToBase64String(signatureBytes);

                // Setting the values in the Authorization header using custom scheme (Hmac)
                request.Headers.Authorization = new AuthenticationHeaderValue(
                    HmacAuthenticationDefaults.AuthenticationScheme,
                    $"{this.hmacHashingMethod}:{this.requestBodyHashingMethod}:{this.appId}:{requestSignatureBase64String}:{nonce}:{requestTimeStamp}");
            }

            var response = await base.SendAsync(request, cancellationToken);

            return response;
        }
    }
}
