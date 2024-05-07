namespace softaware.Authentication.SasToken.Models
{
    public enum QueryParameterHandlingType
    {
        /// <summary>
        /// The SAS uri must not contain additional query parameters additionally to those which were already added when generating the SAS token.
        /// If additional query parameters are present, the request will be rejected.
        /// </summary>
        DenyAdditionalQueryParameters,

        /// <summary>
        /// The SAS uri may contain additional query parameters which will not be validated.
        /// </summary>
        AllowAdditionalQueryParameters,
    }
}
