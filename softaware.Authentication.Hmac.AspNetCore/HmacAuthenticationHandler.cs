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
                    var authenticationHeaderArray = GetAuthenticationValues(rawAuthenticationHeader);

                    if (authenticationHeaderArray != null)
                    {
                        var appId = authenticationHeaderArray[0];
                        var incomingBase64Signature = authenticationHeaderArray[1];
                        var nonce = authenticationHeaderArray[2];
                        var requestTimeStamp = authenticationHeaderArray[3];

                        // Note that we must not dispose the memoryStream here, because the stream is needed in subsequent handlers
                        var memoryStream = new MemoryStream();

                        await this.Request.Body.CopyToAsync(memoryStream);
                        this.Request.Body = memoryStream;

                        try
                        {
                            result.Valid = await this.IsValidRequestAsync(request, memoryStream.ToArray(), appId, incomingBase64Signature, nonce, requestTimeStamp);
                            result.Username = appId;
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

        private async Task<bool> IsValidRequestAsync(HttpRequest req, byte[] body, string appId, string incomingBase64Signature, string nonce, string requestTimeStamp)
        {
            var requestContentBase64String = string.Empty;
            var absoluteUri = string.Concat(
                        this.GetRequestScheme(req),
                        "://",
                        req.Host.ToUriComponent(),
                        req.PathBase.ToUriComponent(),
                        req.Path.ToUriComponent(),
                        req.QueryString.ToUriComponent());
            var requestUri = WebUtility.UrlEncode(absoluteUri.ToLower());
            var requestHttpMethod = req.Method;

            var authorizationProviderResult = await this.Options.AuthorizationProvider.TryGetApiKeyAsync(appId);

            if (!authorizationProviderResult.Found)
            {
                return false;
            }

            if (this.IsReplayRequest(nonce, requestTimeStamp))
            {
                return false;
            }

            var hash = ComputeHash(body);

            if (hash != null)
            {
                requestContentBase64String = Convert.ToBase64String(hash);
            }

            var data = $"{appId}{requestHttpMethod}{requestUri}{requestTimeStamp}{nonce}{requestContentBase64String}";

            var apiKeyBytes = Convert.FromBase64String(authorizationProviderResult.ApiKey);

            var signature = Encoding.UTF8.GetBytes(data);

            using (var hmac = new HMACSHA256(apiKeyBytes))
            {
                byte[] signatureBytes = hmac.ComputeHash(signature);

                return incomingBase64Signature.Equals(Convert.ToBase64String(signatureBytes), StringComparison.Ordinal);
            }
        }

        private static string[] GetAuthenticationValues(string rawAuthenticationHeader)
        {
            var credArray = rawAuthenticationHeader.Split(':');
            return credArray.Length == 4 ? credArray : null;
        }

        private bool IsReplayRequest(string nonce, string requestTimeStamp)
        {
            var nonceInMemory = this.memoryCache.Get(nonce);
            if (nonceInMemory != null)
            {
                return true;
            }

            var epochStart = new DateTime(1970, 01, 01, 0, 0, 0, 0, DateTimeKind.Utc);
            var currentTs = DateTime.UtcNow - epochStart;

            var serverTotalSeconds = Convert.ToInt64(currentTs.TotalSeconds);
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

        private static byte[] ComputeHash(byte[] body)
        {
            using (var md5 = MD5.Create())
            {
                byte[] hash = null;
                if (body.Length != 0)
                {
                    hash = md5.ComputeHash(body);
                }

                return hash;
            }
        }
    }
}
