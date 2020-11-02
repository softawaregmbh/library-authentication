using System.Threading.Tasks;

namespace softaware.Authentication.Hmac.AuthorizationProvider
{
    public interface IHmacAuthorizationProvider
    {
        Task<AuthorizationProviderResult> TryGetApiKeyAsync(string appId);
    }
}
