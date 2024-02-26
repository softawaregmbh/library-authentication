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

        public IHmacAuthorizationProvider AuthorizationProvider { get; set; }

        public HmacAuthenticationSchemeOptions()
        {
            this.MaxRequestAgeInSeconds = HmacAuthenticationDefaults.MaxRequestAgeInSeconds;
            this.AuthenticationScheme = HmacAuthenticationDefaults.AuthenticationScheme;
        }
    }
}
