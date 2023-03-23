using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace softaware.Authentication.Hmac.Client
{
    public class ApiKeyDelegatingHandler : DelegatingHandler
    {
        private readonly string appId;
        private readonly string apiKey;
        private readonly RequestBodyHashingMethod requestBodyHashingMethod;

        public ApiKeyDelegatingHandler(string appId, string apiKey)
            : this(appId, apiKey, RequestBodyHashingMethod.MD5)
        {
        }

        public ApiKeyDelegatingHandler(string appId, string apiKey, RequestBodyHashingMethod requestBodyHashingMethod)
        {
            this.appId = !string.IsNullOrWhiteSpace(appId) ? appId : throw new ArgumentNullException(nameof(appId));
            this.apiKey = !string.IsNullOrWhiteSpace(apiKey) ? apiKey : throw new ArgumentNullException(nameof(apiKey));
            this.requestBodyHashingMethod = requestBodyHashingMethod;

            try
            {
                Convert.FromBase64String(this.apiKey);
            }
            catch (FormatException)
            {
                throw new ArgumentException($"{nameof(apiKey)} must be a valid base64 string.");
            }
        }

        public ApiKeyDelegatingHandler(string appId, string apiKey, HttpMessageHandler innerHandler)
            : this(appId, apiKey, RequestBodyHashingMethod.MD5, innerHandler)
        {
            this.appId = appId ?? throw new ArgumentNullException(nameof(appId));
            this.apiKey = apiKey ?? throw new ArgumentNullException(nameof(apiKey));
        }

        public ApiKeyDelegatingHandler(string appId, string apiKey, RequestBodyHashingMethod requestBodyHashingMethod, HttpMessageHandler innerHandler)
            : base(innerHandler)
        {
            this.appId = appId ?? throw new ArgumentNullException(nameof(appId));
            this.apiKey = apiKey ?? throw new ArgumentNullException(nameof(apiKey));
            this.requestBodyHashingMethod = requestBodyHashingMethod;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var requestContentBase64String = string.Empty;

            var requestUri = WebUtility.UrlEncode(request.RequestUri.AbsoluteUri.ToLower());

            var requestHttpMethod = request.Method.Method;

            // Calculate UNIX time
            var epochStart = new DateTime(1970, 01, 01, 0, 0, 0, 0, DateTimeKind.Utc);
            var timeSpan = DateTime.UtcNow - epochStart;
            var requestTimeStamp = Convert.ToUInt64(timeSpan.TotalSeconds).ToString();

            // create random nonce for each request
            var nonce = Guid.NewGuid().ToString("N");

            // Checking if the request contains body, usually will be null wiht HTTP GET and DELETE
            if (request.Content != null)
            {
                var content = await request.Content.ReadAsByteArrayAsync();
                using (var hashAlgorithm = this.GetHashAlgorithm())
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

            using (var hmac = new HMACSHA256(apiKeyBytes))
            {
                var signatureBytes = hmac.ComputeHash(signature);
                var requestSignatureBase64String = Convert.ToBase64String(signatureBytes);

                // Setting the values in the Authorization header using custom scheme (Hmac)
                request.Headers.Authorization = new AuthenticationHeaderValue(
                    "Hmac",
                    $"{this.appId}:{requestSignatureBase64String}:{nonce}:{requestTimeStamp}");
            }

            var response = await base.SendAsync(request, cancellationToken);

            return response;
        }

        private HashAlgorithm GetHashAlgorithm()
        {
            switch (this.requestBodyHashingMethod)
            {
                case RequestBodyHashingMethod.MD5:
                    return MD5.Create();
                case RequestBodyHashingMethod.SHA256:
                    return SHA256.Create();
                default:
                    throw new NotSupportedException($"requestBodyHashingMethod {requestBodyHashingMethod} is not supported.");
            }
        }
    }
}
