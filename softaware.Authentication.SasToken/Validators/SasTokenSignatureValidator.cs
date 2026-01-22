using Microsoft.Extensions.Primitives;
using softaware.Authentication.SasToken.Generators;
using softaware.Authentication.SasToken.Models;

namespace softaware.Authentication.SasToken.Validators;

public class SasTokenSignatureValidator(SasTokenSignatureGenerator sasTokenSignatureGenerator)
{
    private static readonly HashSet<string> sasQueryParameters = ["sv", "st", "se", "sq", "sp", "sig"];

    public async Task<bool> ValidateAsync(
        string requestPath,
        IEnumerable<KeyValuePair<string, StringValues>> queryParameters,
        CancellationToken cancellationToken)
    {
        var queryParameterValuesByKey = queryParameters.ToDictionary(p => p.Key, p => p.Value);

        if (!queryParameterValuesByKey.TryGetValue("sv", out var sasTokenVersionQueryValue) ||
            !int.TryParse(sasTokenVersionQueryValue, out var sasTokenVersion) ||
            sasTokenVersion != SasTokenVersion.Version1)
        {
            return false;
        }

        if (!queryParameterValuesByKey.TryGetValue("st", out var startDateQueryValue) ||
            !DateTime.TryParse(startDateQueryValue, out var startDate) ||
            DateTime.UtcNow < startDate)
        {
            return false;
        }

        if (!queryParameterValuesByKey.TryGetValue("se", out var endDateQueryValue) ||
            !DateTime.TryParse(endDateQueryValue, out var endDate) ||
            DateTime.UtcNow > endDate)
        {
            return false;
        }

        if (!queryParameterValuesByKey.TryGetValue("sq", out var typeQueryValue))
        {
            return false;
        }

        if (!QueryParameterHandlingTypeExtensions.TryGetQueryParameterHandlingType(typeQueryValue.ToString(), out var queryParameterHandlingType))
        {
            return false;
        }

        HashSet<string> knownParameterKeys = new();
        if (queryParameterValuesByKey.TryGetValue("sp", out var spQueryValue))
        {
            knownParameterKeys = [.. spQueryValue.ToString().Split(',')];
        }

        if (!queryParameterValuesByKey.TryGetValue("sig", out var requestHash))
        {
            return false;
        }

        var generatedHash = await sasTokenSignatureGenerator.GenerateAsync(
            requestPath,
            startDate,
            endDate,
            queryParameterHandlingType,
            GetAdditionalQueryParametersDependingOnType(queryParameterValuesByKey, queryParameterHandlingType, knownParameterKeys),
            cancellationToken);

        return requestHash.ToString().Replace(" ", "+") == generatedHash;
    }

    private static Dictionary<string, StringValues> GetAdditionalQueryParametersDependingOnType(
        Dictionary<string, StringValues> queryParameterValuesByKey,
        QueryParameterHandlingType queryParameterHandlingType,
        ISet<string> knownParameterKeys)
    {
        return queryParameterHandlingType switch
        {
            // In Allow case we only consider the known query parameters when calculating the signature.
            QueryParameterHandlingType.AllowAdditionalQueryParameters => GetKnownQueryParameters(queryParameterValuesByKey, knownParameterKeys),

            // In Deny case, we need to get all query parameters when calculating the signature to ensure that no additional parameters are present.
            QueryParameterHandlingType.DenyAdditionalQueryParameters => GetAllQueryParameters(queryParameterValuesByKey),

            _ => throw new NotSupportedException($"{nameof(queryParameterHandlingType)} {queryParameterHandlingType} is not supported."),
        };
    }

    private static Dictionary<string, StringValues> GetAllQueryParameters(
        Dictionary<string, StringValues> queryParameterValuesByKey
    ) =>
        queryParameterValuesByKey
            .Where(s => !sasQueryParameters.Contains(s.Key))
            .ToDictionary(q => q.Key, q => q.Value);

    private static Dictionary<string, StringValues> GetKnownQueryParameters(
        Dictionary<string, StringValues> queryParameterValuesByKey,
        ISet<string> knownParameterKeys
    ) =>
        queryParameterValuesByKey
            .Where(s => knownParameterKeys.Contains(s.Key))
            .ToDictionary(q => q.Key, q => q.Value);
}
