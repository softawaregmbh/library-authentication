using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication;

namespace softaware.Authentication.Hmac.AspNetCore
{
    public class HmacAuthenticationSchemeOptions : AuthenticationSchemeOptions
    {
        public long MaxRequestAgeInSeconds { get; set; }

        public string AuthenticationScheme { get; set; }

        public IDictionary<string, string> HmacAuthenticatedApps { get; set; } = new Dictionary<string, string>();

        public HmacAuthenticationSchemeOptions()
        {
            this.MaxRequestAgeInSeconds = HmacAuthenticationDefaults.MaxRequestAgeInSeconds;
            this.AuthenticationScheme = HmacAuthenticationDefaults.AuthenticationScheme;
        }
    }
}
