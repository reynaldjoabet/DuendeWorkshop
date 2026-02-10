using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;

class MyCustomIdentityProviderStore : IIdentityProviderStore
{
    public Task<IEnumerable<IdentityProviderName>> GetAllSchemeNamesAsync()
    {
        throw new NotImplementedException();
    }

    public Task<IdentityProvider?> GetBySchemeAsync(string scheme)
    {
        throw new NotImplementedException();
    }
}