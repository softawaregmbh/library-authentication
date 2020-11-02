namespace softaware.Authentication.Hmac.AuthorizationProvider
{
    public struct AuthorizationProviderResult
    {
        public AuthorizationProviderResult(string appId, bool found, string apiKey)
        {
            this.AppId = appId;
            this.Found = found;
            this.ApiKey = apiKey;
        }

        /// <summary>
        /// The HMAC App Id.
        /// </summary>
        public string AppId { get; }

        /// <summary>
        /// <see langword="True"/>, if the specified HMAC app has been found based on the <see cref="AppId"/>.
        /// </summary>
        public bool Found { get; }

        /// <summary>
        /// The API key for the specified <see cref="AppId"/>.
        /// </summary>
        public string ApiKey { get; }
    }
}
