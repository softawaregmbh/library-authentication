using System.Threading.Tasks;

namespace softaware.Authentication.Basic.AspNetCore.AuthorizationProvider
{
    public interface IBasicAuthorizationProvider
    {
        Task<bool> IsAuthorizedAsync(string username, string password);
    }
}
