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
