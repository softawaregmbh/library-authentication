using System;
using System.Security.Cryptography;
using softaware.Authentication.Hmac.Client;

namespace softaware.Authentication.Hmac
{
    public static class HashingMethodExtensions
    {
        public static HashAlgorithm CreateHashAlgorithm(this RequestBodyHashingMethod requestBodyHashingMethod) => requestBodyHashingMethod switch
        {
            RequestBodyHashingMethod.MD5 => MD5.Create(),
            RequestBodyHashingMethod.SHA1 => SHA1.Create(),
            RequestBodyHashingMethod.SHA256 => SHA256.Create(),
            RequestBodyHashingMethod.SHA384 => SHA384.Create(),
            RequestBodyHashingMethod.SHA512 => SHA512.Create(),
            _ => throw new NotSupportedException($"requestBodyHashingMethod {requestBodyHashingMethod} is not supported."),
        };

        public static HMAC CreateHmac(this HmacHashingMethod hmacHashingMethod, byte[] key) => hmacHashingMethod switch
        {
            HmacHashingMethod.HMACMD5 => new HMACMD5(key),
            HmacHashingMethod.HMACSHA1 => new HMACSHA1(key),
            HmacHashingMethod.HMACSHA256 => new HMACSHA256(key),
            HmacHashingMethod.HMACSHA384 => new HMACSHA384(key),
            HmacHashingMethod.HMACSHA512 => new HMACSHA512(key),
            _ => throw new NotSupportedException($"hmacHashingMethod {hmacHashingMethod} is not supported."),
        };
    }
}
