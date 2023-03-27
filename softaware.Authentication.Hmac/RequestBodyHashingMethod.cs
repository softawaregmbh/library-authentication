namespace softaware.Authentication.Hmac.Client
{
    /// <summary>
    /// Defines which hashing method should be used for the http request body.
    /// </summary>
    public enum RequestBodyHashingMethod
    {
        /// <summary>
        /// Due to collision problems with MD5 and SHA-1, Microsoft recommends a security model based on SHA-256 or better.
        /// </summary>
        MD5,

        /// <summary>
        /// Due to collision problems with MD5 and SHA-1, Microsoft recommends a security model based on SHA-256 or better.
        /// </summary>
        SHA1,
        SHA256,
        SHA384,
        SHA512,
    }
}
