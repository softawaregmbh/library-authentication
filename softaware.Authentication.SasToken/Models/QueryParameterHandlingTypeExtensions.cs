namespace softaware.Authentication.SasToken.Models
{
    public static class QueryParameterHandlingTypeExtensions
    {
        public static string GetQueryParameterValue(QueryParameterHandlingType queryParameterHandlingType)
        {
            return queryParameterHandlingType switch
            {
                QueryParameterHandlingType.AllowAdditionalQueryParameters => "a",
                QueryParameterHandlingType.DenyAdditionalQueryParameters => "d",
                _ => throw new NotSupportedException($"{nameof(queryParameterHandlingType)} {queryParameterHandlingType} is not supported."),
            };
        }

        public static QueryParameterHandlingType GetQueryParameterHandlingType(string queryParameterValue)
        {
            return queryParameterValue switch
            {
                "a" => QueryParameterHandlingType.AllowAdditionalQueryParameters,
                "d" => QueryParameterHandlingType.DenyAdditionalQueryParameters,
                _ => throw new NotSupportedException($"{nameof(queryParameterValue)} {queryParameterValue} is not supported."),
            };
        }

        public static bool TryGetQueryParameterHandlingType(string queryParameterValue, out QueryParameterHandlingType queryParameterHandlingType)
        {
            try
            {
                queryParameterHandlingType = GetQueryParameterHandlingType(queryParameterValue);
                return true;
            }
            catch (NotSupportedException)
            {
                queryParameterHandlingType = default;
                return false;
            }
        }
    }
}
