using System;
using System.IO;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using softaware.Authentication.Hmac.Client;

namespace softaware.Authentication.Hmac.AspNetCore
{
    internal class HmacAuthenticationHandler : AuthenticationHandler<HmacAuthenticationSchemeOptions>
    {
        private class ValidationResult
        {
            public bool Valid { get; set; }

            /// <summary>
            /// Only valid if <see cref="Valid"/> is true.
            /// </summary>
            public string Username { get; set; }
        }

        private readonly IMemoryCache memoryCache = new MemoryCache(new MemoryCacheOptions());

        public HmacAuthenticationHandler(IOptionsMonitor<HmacAuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (this.Options.AuthorizationProvider == null)
            {
                throw new ArgumentException($"{nameof(this.Options.AuthorizationProvider)} in the options is absolutely necessary.");
            }

            if (!this.Request.Headers.TryGetValue("Authorization", out var authorization))
            {
                return AuthenticateResult.Fail("Missing 'Authorization' header.");
            }

            var validationResult = await this.ValidateAsync(this.Request);

            if (validationResult.Valid)
            {
                var claimsToSet = new Claim[] { new Claim(ClaimTypes.NameIdentifier, validationResult.Username) };

                var principal = new ClaimsPrincipal(new ClaimsIdentity(claimsToSet, HmacAuthenticationDefaults.AuthenticationType, ClaimTypes.NameIdentifier, ClaimTypes.Role));
                var ticket = new AuthenticationTicket(principal, new AuthenticationProperties(), this.Options.AuthenticationScheme);
                return AuthenticateResult.Success(ticket);
            }

            return AuthenticateResult.Fail("Authentication failed");
        }

        private async Task<ValidationResult> ValidateAsync(HttpRequest request)
        {
            var result = new ValidationResult();

            if (this.Request.Headers.TryGetValue("Authorization", out var header))
            {
                var authenticationHeader = AuthenticationHeaderValue.Parse(header);
                if (this.Options.AuthenticationScheme.Equals(authenticationHeader.Scheme, StringComparison.OrdinalIgnoreCase))
                {
                    var rawAuthenticationHeader = authenticationHeader.Parameter;
                    var (isValidHeader, values) = GetAuthenticationValues(rawAuthenticationHeader);

                    if (isValidHeader)
                    {
                        // Note that we must not dispose the memoryStream here, because the stream is needed in subsequent handlers
                        var memoryStream = new MemoryStream();

                        await this.Request.Body.CopyToAsync(memoryStream);
                        this.Request.Body = memoryStream;

                        try
                        {
                            result.Valid = await this.IsValidRequestAsync(request, memoryStream.ToArray(), values);
                            result.Username = values.AppId;
                        }
                        finally
                        {
                            // We need to reset the stream so that subsequent handlers have a fresh stream which they can consume.
                            memoryStream.Seek(0, SeekOrigin.Begin);
                        }
                    }
                }
            }

            return result;
        }

        private async Task<bool> IsValidRequestAsync(HttpRequest req, byte[] body, HmacAuthenticationHeaderValues values)
        {
            var absoluteUri = string.Concat(
                        this.GetRequestScheme(req),
                        "://",
                        req.Host.ToUriComponent(),
                        req.PathBase.ToUriComponent(),
                        req.Path.ToUriComponent(),
                        req.QueryString.ToUriComponent());
            var requestUri = WebUtility.UrlEncode(absoluteUri.ToLower());
            var requestHttpMethod = req.Method;

            var authorizationProviderResult = await this.Options.AuthorizationProvider.TryGetApiKeyAsync(values.AppId);

            if (!authorizationProviderResult.Found)
            {
                return false;
            }

            if (this.IsReplayRequest(values.Nonce, values.RequestTimeStamp))
            {
                return false;
            }

            var requestContentBase64String = ComputeRequestBodyBase64Hash(body, values.RequestBodyHashingMethod);

            var apiKeyBytes = Convert.FromBase64String(authorizationProviderResult.ApiKey);
            using (var hmac = values.HmacHashingMethod.CreateHmac(apiKeyBytes))
            {
                var computedSignature = ComputeBase64Signature(
                    values.AppId,
                    requestHttpMethod,
                    requestUri,
                    values.RequestTimeStamp,
                    values.Nonce,
                    requestContentBase64String,
                    hmac);

                var isValid = values.IncomingBase64Signature.Equals(computedSignature, StringComparison.Ordinal);
                return isValid;
            }
        }

        private static string ComputeBase64Signature(
            string appId,
            string requestHttpMethod,
            string requestUri,
            string requestTimeStamp,
            string nonce,
            string requestContentBase64String,
            HMAC hmac)
        {
            var data = $"{appId}{requestHttpMethod}{requestUri}{requestTimeStamp}{nonce}{requestContentBase64String}";
            var signature = Encoding.UTF8.GetBytes(data);
            byte[] signatureBytes = hmac.ComputeHash(signature);

            return Convert.ToBase64String(signatureBytes);
        }

        private static (bool IsValidHeader, HmacAuthenticationHeaderValues Values) GetAuthenticationValues(string rawAuthenticationHeader)
        {
            var authenticationHeaderArray = rawAuthenticationHeader.Split(':');

            var isValidHeader = authenticationHeaderArray.Length == 4 || authenticationHeaderArray.Length == 6;
            var hasHashingAlgorithmProperties = authenticationHeaderArray.Length == 6;

            if (!isValidHeader)
            {
                return (IsValidHeader: false, null);
            }

            var hmacHashingMethod = hasHashingAlgorithmProperties
                ? Enum.TryParse<HmacHashingMethod>(authenticationHeaderArray[0], out var hhm) ? hhm : throw new NotSupportedException($"Hmac hashing method {authenticationHeaderArray[0]} is not supported.")
                : HmacHashingMethod.HMACSHA256; // Default value in previous library versions before changing header to include hashing algorithm.

            var requestBodyHashingMethod = hasHashingAlgorithmProperties
                ? Enum.TryParse<RequestBodyHashingMethod>(authenticationHeaderArray[1], out var rhm) ? rhm : throw new NotSupportedException($"Request body hashing method {authenticationHeaderArray[1]} is not supported.")
                : RequestBodyHashingMethod.MD5; // Default value in previous library versions before changing header to include hashing algorithm.

            var appId = hasHashingAlgorithmProperties ? authenticationHeaderArray[2] : authenticationHeaderArray[0];
            var incomingBase64Signature = hasHashingAlgorithmProperties ? authenticationHeaderArray[3] : authenticationHeaderArray[1];
            var nonce = hasHashingAlgorithmProperties ? authenticationHeaderArray[4] : authenticationHeaderArray[2];
            var requestTimeStamp = hasHashingAlgorithmProperties ? authenticationHeaderArray[5] : authenticationHeaderArray[3];

            var values = new HmacAuthenticationHeaderValues(
                hmacHashingMethod,
                requestBodyHashingMethod,
                appId,
                incomingBase64Signature,
                nonce,
                requestTimeStamp);

            return (IsValidHeader: true, values);
        }

        private bool IsReplayRequest(string nonce, string requestTimeStamp)
        {
            var nonceInMemory = this.memoryCache.Get(nonce);
            if (nonceInMemory != null)
            {
                return true;
            }

            var serverTotalSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var requestTotalSeconds = Convert.ToInt64(requestTimeStamp);
            var diff = Math.Abs(serverTotalSeconds - requestTotalSeconds);

            if (diff > this.Options.MaxRequestAgeInSeconds)
            {
                return true;
            }

            this.memoryCache.Set(nonce, requestTimeStamp, DateTimeOffset.UtcNow.AddSeconds(this.Options.MaxRequestAgeInSeconds));
            return false;
        }

        private string GetRequestScheme(HttpRequest req)
        {
            if (this.Options.TrustProxy && req.Headers.TryGetValue("X-Forwarded-Proto", out var scheme))
            {
                return scheme;
            }

            return req.Scheme;
        }

        private static string ComputeRequestBodyBase64Hash(byte[] body, RequestBodyHashingMethod requestBodyHashingMethod)
        {
            using (var hashAlgorithm = requestBodyHashingMethod.CreateHashAlgorithm())
            {
                if (body.Length != 0)
                {
                    var hash = hashAlgorithm.ComputeHash(body);
                    return Convert.ToBase64String(hash);
                }
                else
                {
                    return string.Empty;
                }
            }
        }

        private class HmacAuthenticationHeaderValues
        {
            public HmacAuthenticationHeaderValues(
                HmacHashingMethod hmacHashingMethod,
                RequestBodyHashingMethod requestBodyHashingMethod,
                string appId,
                string incomingBase64Signature,
                string nonce,
                string requestTimeStamp)
            {
                HmacHashingMethod = hmacHashingMethod;
                RequestBodyHashingMethod = requestBodyHashingMethod;
                AppId = appId;
                IncomingBase64Signature = incomingBase64Signature;
                Nonce = nonce;
                RequestTimeStamp = requestTimeStamp;
            }

            public HmacHashingMethod HmacHashingMethod { get; }
            public RequestBodyHashingMethod RequestBodyHashingMethod { get; }
            public string AppId { get; }
            public string IncomingBase64Signature { get; }
            public string Nonce { get; }
            public string RequestTimeStamp { get; }
        }
    }
}
