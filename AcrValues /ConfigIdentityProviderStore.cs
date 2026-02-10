
#nullable enable

using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;
using Microsoft.Extensions.Options;

namespace IdentityServerHost;

internal class ConfigIdentityProviderStore : IIdentityProviderStore
{
    private readonly IOptionsMonitor<FederatedGatewayOptions> _options;

    public ConfigIdentityProviderStore(IOptionsMonitor<FederatedGatewayOptions> options)
    {
        _options = options;
    }

    public Task<IEnumerable<IdentityProviderName>> GetAllSchemeNamesAsync()
    {
        var providers = _options.CurrentValue.OidcProviders ?? new List<OidcProvider>();
        var items = providers.Select(p => new IdentityProviderName
        {
            Enabled = p.Enabled,
            DisplayName = p.DisplayName,
            Scheme = p.Scheme
        });

        return Task.FromResult(items);
    }

    public Task<IdentityProvider?> GetBySchemeAsync(string scheme)
    {
        var provider = _options.CurrentValue.OidcProviders
            ?.FirstOrDefault(p => string.Equals(p.Scheme, scheme, StringComparison.Ordinal));

        return Task.FromResult<IdentityProvider?>(provider);
    }
}