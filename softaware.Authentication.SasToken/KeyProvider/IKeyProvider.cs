namespace softaware.Authentication.SasToken.KeyProvider
{
    public interface IKeyProvider
    {
        Task<string> GetKeyAsync(CancellationToken cancellationToken);
    }
}
