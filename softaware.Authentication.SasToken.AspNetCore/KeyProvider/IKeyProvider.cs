namespace softaware.Authentication.SasToken.AspNetCore.KeyProvider
{
    public interface IKeyProvider
    {
        Task<string> GetKeyAsync();
    }
}
