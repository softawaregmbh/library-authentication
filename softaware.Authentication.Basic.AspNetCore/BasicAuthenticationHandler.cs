using System;
using System.Collections.Generic;
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
        private class ValidationResult
        {
            public bool Valid { get; set; }

            public string Username { get; set; }

            public string Password { get; set; }
        }

        public BasicAuthenticationHandler(IOptionsMonitor<BasicAuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (this.Options.AuthorizationProvider == null)
            {
                throw new ArgumentException($"{nameof(this.Options.AuthorizationProvider)} is absolutely necessary.");
            }

            if (!this.Request.Headers.TryGetValue("Authorization", out var authorization))
            {
                return AuthenticateResult.Fail("Missing 'Authorization' header.");
            }

            if (!authorization.ToString().StartsWith("Basic"))
            {
                return AuthenticateResult.Fail("'Authorization' header MUST start with 'Basic'.");
            }

            var validationResult = await this.ValidateAsync(this.Request);

            if (validationResult.Valid)
            {
                var claimsToSet = new List<Claim> 
                { 
                    new Claim(ClaimTypes.NameIdentifier, validationResult.Username) 
                };

                if (this.Options.AddPasswordAsClaim)
                {
                    claimsToSet.Add(new Claim(this.Options.PasswordClaimType, validationResult.Password));
                }

                var principal = new ClaimsPrincipal(new ClaimsIdentity(claimsToSet, BasicAuthenticationDefaults.AuthenticationType, ClaimTypes.NameIdentifier, ClaimTypes.Role));
                var ticket = new AuthenticationTicket(principal, new AuthenticationProperties(), this.Options.AuthenticationScheme);
                return AuthenticateResult.Success(ticket);
            }

            return AuthenticateResult.Fail("Authentication failed");
        }

        private async Task<ValidationResult> ValidateAsync(HttpRequest request)
        {
            var result = new ValidationResult();

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
                        return result;
                    }

                    result.Valid = await this.Options.AuthorizationProvider.IsAuthorizedAsync(splittedUsernamePassword[0], splittedUsernamePassword[1]);
                    result.Username = splittedUsernamePassword[0];
                    result.Password = splittedUsernamePassword[1];
                }
            }

            return result;
        }
    }
}
