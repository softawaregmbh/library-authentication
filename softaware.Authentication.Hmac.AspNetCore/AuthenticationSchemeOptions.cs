using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication;
using softaware.Authentication.Hmac.AuthorizationProvider;

namespace softaware.Authentication.Hmac.AspNetCore
{
    public class HmacAuthenticationSchemeOptions : AuthenticationSchemeOptions
    {
        public long MaxRequestAgeInSeconds { get; set; }

        public string AuthenticationScheme { get; set; }

        /// <summary>
        /// If <see langword="true"/>, the request scheme from the 'X-Forwarded-Proto' header is used to validate the request.
        /// </summary>
        public bool TrustProxy { get; set; }

        /// <summary>
        /// If <see langword="true"/>, the request body hash will be validated with MD5 hash and SHA265 hash.
        /// Note that this setting is only relevant when the http request has a body.
        /// (Default: <see langword="true"/>)
        /// </summary>
        /// <remarks>
        /// This setting helps upgrading from MD5 to SHA256 hash without breaking changes.
        /// </remarks>
        [Obsolete("Will be removed in the next major version as only SHA256 request body hashing will be supported in future.")]
        public bool AllowMD5AndSHA256RequestBodyHash { get; set; } = true;

        private IDictionary<string, string> hmacAuthenticatedApps = new Dictionary<string, string>();

        [Obsolete("Please use the MemoryHmacAuthenticationProvider for configuring the HMAC apps in-memory. This property will be removed in future versions of this package.", error: false)]
        public IDictionary<string, string> HmacAuthenticatedApps
        {
            get { return this.hmacAuthenticatedApps; }
            set
            {
                this.hmacAuthenticatedApps = value;

                // temporary backwards compatible solution as long as we support HmacAuthenticatedApps.
                this.AuthorizationProvider = new MemoryHmacAuthenticationProvider(this.hmacAuthenticatedApps);
            }
        }

        public IHmacAuthorizationProvider AuthorizationProvider { get; set; }

        public HmacAuthenticationSchemeOptions()
        {
            this.MaxRequestAgeInSeconds = HmacAuthenticationDefaults.MaxRequestAgeInSeconds;
            this.AuthenticationScheme = HmacAuthenticationDefaults.AuthenticationScheme;
        }
    }
}
