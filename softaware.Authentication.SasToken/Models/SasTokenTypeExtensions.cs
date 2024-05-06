namespace softaware.Authentication.SasToken.Models
{
    public static class SasTokenTypeExtensions
    {
        public static string GetQueryParameterName(SasTokenType sasTokenType)
        {
            return sasTokenType switch
            {
                SasTokenType.ConsiderAllQueryParameters => "f",
                SasTokenType.IgnoreAdditionalQueryParameters => "p",
                _ => throw new NotSupportedException($"{nameof(sasTokenType)} {sasTokenType} is not supported."),
            };
        }
    }
}
