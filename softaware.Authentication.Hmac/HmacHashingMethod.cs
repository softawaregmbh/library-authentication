namespace softaware.Authentication.Hmac.Client
{
    /// <summary>
    /// Defines which hashing method should be used for hashing the HMAC signature in the header.
    /// </summary>
    public enum HmacHashingMethod
    {

        /// <summary>
        /// Due to collision problems with MD5 and SHA-1, Microsoft recommends a security model based on SHA-256 or better.
        /// </summary>
        HMACMD5,

        /// <summary>
        /// Due to collision problems with MD5 and SHA-1, Microsoft recommends a security model based on SHA-256 or better.
        /// </summary>
        HMACSHA1,
        HMACSHA256,
        HMACSHA384,
        HMACSHA512,
    }
}
