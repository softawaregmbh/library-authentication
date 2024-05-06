namespace softaware.Authentication.SasToken.Models
{
    public enum SasTokenType
    {
        /// <summary>
        /// Additionally sent query parameters (additionally to the SAS query parameters) are ignored when validating the SAS token signature.
        /// </summary>
        IgnoreAdditionalQueryParameters,

        /// <summary>
        /// All sent query parameters are considered when validating the SAS token signature.
        /// </summary>
        ConsiderAllQueryParameters,
    }
}
