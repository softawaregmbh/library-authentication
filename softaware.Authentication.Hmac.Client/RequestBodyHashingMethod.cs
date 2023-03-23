using System;

namespace softaware.Authentication.Hmac.Client
{
    /// <summary>
    /// Defines which hashing method should be used for the http request body.
    /// </summary>
    public enum RequestBodyHashingMethod
    {
        [Obsolete("Will be removed in the next major version release.")]
        MD5 = 0,
        SHA256 = 1
    }
}
