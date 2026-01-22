using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using softaware.Authentication.SasToken.Validators;

namespace softaware.Authentication.SasToken.AspNetCore
{
    public class SasTokenAuthenticationHandler(
        IOptionsMonitor<SasTokenAuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        SasTokenSignatureValidator sasTokenSignatureValidator)
        : AuthenticationHandler<SasTokenAuthenticationSchemeOptions>(options, logger, encoder)
    {
        protected async override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (await sasTokenSignatureValidator.ValidateAsync(this.Request.Path, this.Request.Query, CancellationToken.None))
            {
                var identity = new ClaimsIdentity(SasTokenAuthenticationDefaults.AuthenticationType, ClaimTypes.NameIdentifier, ClaimTypes.Role);

                if (!string.IsNullOrEmpty(this.Options.NameIdentifierQueryParameter) &&
                    this.Request.Query.TryGetValue(this.Options.NameIdentifierQueryParameter, out var nameIdentifierQueryParameterValue))
                {
                    identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, nameIdentifierQueryParameterValue.ToString()));
                }

                var principal = new ClaimsPrincipal(identity);
                var ticket = new AuthenticationTicket(principal, new AuthenticationProperties(), this.Options.AuthenticationScheme);
                return AuthenticateResult.Success(ticket);
            }

            return AuthenticateResult.Fail("Authentication failed");
        }
    }
}
