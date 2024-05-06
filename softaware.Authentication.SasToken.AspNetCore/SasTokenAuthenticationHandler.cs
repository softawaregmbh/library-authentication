using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using softaware.Authentication.SasToken.Generators;
using softaware.Authentication.SasToken.Models;

namespace softaware.Authentication.SasToken.AspNetCore
{
    public class SasTokenAuthenticationHandler(
        IOptionsMonitor<SasTokenAuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        SasTokenSignatureGenerator sasTokenSignatureGenerator)
        : AuthenticationHandler<SasTokenAuthenticationSchemeOptions>(options, logger, encoder)
    {
        private readonly SasTokenSignatureGenerator sasTokenSignatureGenerator = sasTokenSignatureGenerator;

        protected async override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (await this.ValidateAsync(this.Request, CancellationToken.None))
            {
                var identity = new ClaimsIdentity(SasTokenAuthenticationDefaults.AuthenticationType, ClaimTypes.NameIdentifier, ClaimTypes.Role);
                identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, this.Request.Query["sig"]!));
                var principal = new ClaimsPrincipal(identity);
                var ticket = new AuthenticationTicket(principal, new AuthenticationProperties(), this.Options.AuthenticationScheme);
                return AuthenticateResult.Success(ticket);
            }

            return AuthenticateResult.Fail("Authentication failed");
        }

        private async Task<bool> ValidateAsync(HttpRequest request, CancellationToken cancellationToken)
        {
            var queryString = request.Query;

            if (!queryString.TryGetValue("sv", out var sasTokenVersionQueryValue) ||
                !int.TryParse(sasTokenVersionQueryValue, out var sasTokenVersion) ||
                sasTokenVersion != SasTokenVersion.Version1)
            {
                return false;
            }

            if (!queryString.TryGetValue("st", out var startDateQueryValue) ||
                !DateTime.TryParse(startDateQueryValue, out var startDate) ||
                DateTime.UtcNow < startDate)
            {
                return false;
            }

            if (!queryString.TryGetValue("se", out var endDateQueryValue) ||
                !DateTime.TryParse(endDateQueryValue, out var endDate) ||
                DateTime.UtcNow > endDate)
            {
                return false;
            }

            if (!queryString.TryGetValue("stt", out var typeQueryValue))
            {
                return false;
            }

            SasTokenType sasTokenType;
            if (typeQueryValue == "f")
            {
                sasTokenType = SasTokenType.ConsiderAllQueryParameters;
            }
            else if (typeQueryValue == "p")
            {
                sasTokenType = SasTokenType.IgnoreAdditionalQueryParameters;
            }
            else
            {
                return false;
            }

            if (!queryString.TryGetValue("sig", out var requestHash))
            {
                return false;
            }

            var generatedHash = await this.sasTokenSignatureGenerator.GenerateAsync(
                startDate,
                endDate,
                sasTokenType,
                request.Path,
                GetAdditionalQueryParametersDependingOnType(request, sasTokenType),
                cancellationToken);

            return requestHash.ToString().Replace(" ", "+") == generatedHash;
        }

        private static string[] GetAdditionalQueryParametersDependingOnType(HttpRequest request, SasTokenType sasTokenType)
        {
            return sasTokenType switch
            {
                SasTokenType.ConsiderAllQueryParameters => GetAdditionalQueryParameters(request),
                SasTokenType.IgnoreAdditionalQueryParameters => [],
                _ => throw new NotSupportedException($"{nameof(sasTokenType)} {sasTokenType} is not supported."),
            };
        }

        private static string[] GetAdditionalQueryParameters(HttpRequest request) =>
            request.Query
                .Where(s => s.Key != "sv" && s.Key != "st" && s.Key != "se" && s.Key != "stt" && s.Key != "sig").Select(s => $"{s.Key}={s.Value}")
                .ToArray();
    }
}
