﻿using System.Collections.Immutable;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
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
        private static readonly string[] sasQueryParameters = ["sv", "st", "se", "sq", "sp", "sig"];
        private readonly SasTokenSignatureGenerator sasTokenSignatureGenerator = sasTokenSignatureGenerator;

        protected async override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (await this.ValidateAsync(this.Request, CancellationToken.None))
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

            if (!queryString.TryGetValue("sq", out var typeQueryValue))
            {
                return false;
            }

            if (!QueryParameterHandlingTypeExtensions.TryGetQueryParameterHandlingType(typeQueryValue.ToString(), out var queryParameterHandlingType))
            {
                return false;
            }

            var knownParameterKeys = new HashSet<string>();
            if (queryString.TryGetValue("sp", out var spQueryValue))
            {
                knownParameterKeys = spQueryValue.ToString().Split(',').ToHashSet();
            }

            if (!queryString.TryGetValue("sig", out var requestHash))
            {
                return false;
            }

            var generatedHash = await this.sasTokenSignatureGenerator.GenerateAsync(
                request.Path,
                startDate,
                endDate,
                queryParameterHandlingType,
                GetAdditionalQueryParametersDependingOnType(request, queryParameterHandlingType, knownParameterKeys),
                cancellationToken);

            return requestHash.ToString().Replace(" ", "+") == generatedHash;
        }

        private static Dictionary<string, StringValues> GetAdditionalQueryParametersDependingOnType(
            HttpRequest request,
            QueryParameterHandlingType queryParameterHandlingType,
            ISet<string> knownParameterKeys)
        {
            return queryParameterHandlingType switch
            {
                // In Allow case we only consider the known query parameters when calculating the signature.
                QueryParameterHandlingType.AllowAdditionalQueryParameters => GetKnownQueryParameters(request, knownParameterKeys),

                // In Deny case, we need to get all query parameters when calculating the signature to ensure that no additional parameters are present.
                QueryParameterHandlingType.DenyAdditionalQueryParameters => GetAllQueryParameters(request),

                _ => throw new NotSupportedException($"{nameof(queryParameterHandlingType)} {queryParameterHandlingType} is not supported."),
            };
        }

        private static Dictionary<string, StringValues> GetAllQueryParameters(HttpRequest request) =>
            request.Query
                .Where(s => !sasQueryParameters.Contains(s.Key))
                .ToDictionary(q => q.Key, q => q.Value);

        private static Dictionary<string, StringValues> GetKnownQueryParameters(HttpRequest request, ISet<string> knownParameterKeys) =>
            request.Query
                .Where(s => knownParameterKeys.Contains(s.Key))
                .ToDictionary(q => q.Key, q => q.Value);
    }
}
