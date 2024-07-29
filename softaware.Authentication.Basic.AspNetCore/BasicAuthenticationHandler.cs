using System;
using System.Collections.Generic;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace softaware.Authentication.Basic.AspNetCore
{
    internal class BasicAuthenticationHandler(
        IOptionsMonitor<BasicAuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : AuthenticationHandler<BasicAuthenticationSchemeOptions>(options, logger, encoder)
    {
        private class ValidationResult
        {
            public bool Valid { get; set; }

            public string Username { get; set; }

            public string Password { get; set; }
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (this.Options.AuthorizationProvider == null)
            {
                throw new ArgumentException($"{nameof(this.Options.AuthorizationProvider)} is absolutely necessary.");
            }

            if (!Request.Headers.TryGetValue("Authorization", out var authorization))
            {
                return AuthenticateResult.Fail("Missing 'Authorization' header.");
            }

            if (!authorization.ToString().StartsWith("Basic"))
            {
                return AuthenticateResult.Fail("'Authorization' header MUST start with 'Basic'.");
            }

            var validationResult = await this.ValidateAsync();

            if (validationResult.Valid)
            {
                var claimsToSet = new List<Claim>
                {
                    new(ClaimTypes.NameIdentifier, validationResult.Username)
                };

                if (this.Options.AddPasswordAsClaim)
                {
                    claimsToSet.Add(new(this.Options.PasswordClaimType, validationResult.Password));
                }

                var principal = new ClaimsPrincipal(new ClaimsIdentity(claimsToSet, BasicAuthenticationDefaults.AuthenticationType, ClaimTypes.NameIdentifier, ClaimTypes.Role));
                var ticket = new AuthenticationTicket(principal, new AuthenticationProperties(), this.Options.AuthenticationScheme);
                return AuthenticateResult.Success(ticket);
            }

            return AuthenticateResult.Fail("Authentication failed");
        }

        private async Task<ValidationResult> ValidateAsync()
        {
            var result = new ValidationResult();

            if (this.Request.Headers.TryGetValue("Authorization", out var header))
            {
                var authenticationHeader = AuthenticationHeaderValue.Parse(header);
                if (this.Options.AuthenticationScheme.Equals(authenticationHeader.Scheme, StringComparison.OrdinalIgnoreCase))
                {
                    // Decode from Base64 to string
                    var decodedUsernamePassword = Encoding.UTF8.GetString(Convert.FromBase64String(authenticationHeader.Parameter));

                    var indexOfFirstColon = decodedUsernamePassword.IndexOf(':');
                    if (indexOfFirstColon == -1)
                    {
                        return result;
                    }

                    var username = decodedUsernamePassword[..indexOfFirstColon];
                    var password = decodedUsernamePassword[(indexOfFirstColon + 1)..];

                    result.Valid = await Options.AuthorizationProvider.IsAuthorizedAsync(
                        username, password);

                    result.Username = username;
                    result.Password = password;
                }
            }

            return result;
        }
    }
}
