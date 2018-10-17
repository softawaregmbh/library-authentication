using System;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using softaware.Authentication.Basic;
using softaware.Authentication.Basic.AspNetCore;

namespace softaware.Authentication.Hmac.AspNetCore
{
    internal class BasicAuthenticationHandler : AuthenticationHandler<BasicAuthenticationSchemeOptions>
    {
        public BasicAuthenticationHandler(IOptionsMonitor<BasicAuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (this.Options.AuthorizationProvider == null)
            {
                throw new ArgumentException($"{this.Options.AuthorizationProvider} is absolutely necessary.");
            }

            if (!this.Request.Headers.TryGetValue("Authorization", out var authorization))
            {
                return AuthenticateResult.Fail("Missing 'Authorization' header.");
            }

            if (!authorization.ToString().StartsWith("Basic"))
            {
                return AuthenticateResult.Fail("'Authorization' header MUST start with 'Basic'.");
            }

            var valid = await this.ValidateAsync(this.Request);

            if (valid)
            {
                var principal = new ClaimsPrincipal(new ClaimsIdentity(BasicAuthenticationDefaults.AuthenticationType));
                var ticket = new AuthenticationTicket(principal, new AuthenticationProperties(), this.Options.AuthenticationScheme);
                return AuthenticateResult.Success(ticket);
            }

            return AuthenticateResult.Fail("Authentication failed");
        }

        private async Task<bool> ValidateAsync(HttpRequest request)
        {
            if (this.Request.Headers.TryGetValue("Authorization", out var header)) {
                var authenticationHeader = AuthenticationHeaderValue.Parse(header);
                if (this.Options.AuthenticationScheme.Equals(authenticationHeader.Scheme, StringComparison.OrdinalIgnoreCase))
                {
                    // Decode from Base64 to string
                    var decodedUsernamePassword = Encoding.UTF8.GetString(Convert.FromBase64String(authenticationHeader.Parameter));
                    // Split username and password
                    var splittedUsernamePassword = decodedUsernamePassword.Split(':');
                    if (splittedUsernamePassword.Length != 2) // username and password must set
                    {
                        return false;
                    }

                    return await this.Options.AuthorizationProvider.IsAuthorizedAsync(splittedUsernamePassword[0], splittedUsernamePassword[1]);
                }
            }

            return false;
        }
    }
}
