using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Threading.Tasks;

namespace softaware.Authentication.Basic.AspNetCore.AuthorizationProvider
{
    public class SecureMemoryBasicAuthenticationProvider : IBasicAuthorizationProvider
    {
        private readonly IReadOnlyDictionary<string, SecureString> credentials;

        public SecureMemoryBasicAuthenticationProvider(IReadOnlyDictionary<string, string> credentials)
        {
            this.credentials = credentials.ToDictionary(c => c.Key, c => this.GetSecuredString(c.Value));
        }

        public SecureMemoryBasicAuthenticationProvider(IReadOnlyDictionary<string, SecureString> credentials)
        {
            this.credentials = credentials.ToDictionary(c => c.Key, c => c.Value);
        }

        public Task<bool> IsAuthorizedAsync(string username, string password)
        {
            if (this.credentials.TryGetValue(username, out var secureString))
            {
                IntPtr valuePtr = IntPtr.Zero;
                try
                {
                    valuePtr = Marshal.SecureStringToGlobalAllocUnicode(secureString);
                    return Task.FromResult(Marshal.PtrToStringUni(valuePtr) == password);
                }
                finally
                {
                    Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
                }
            }

            return Task.FromResult(false);
        }

        private SecureString GetSecuredString(string value)
        {
            var secureString = new SecureString();

            for (int i = 0; i < value.Length; i++)
            {
                secureString.AppendChar(value[i]);
            }

            secureString.MakeReadOnly();
            return secureString;
        }
    }
}
