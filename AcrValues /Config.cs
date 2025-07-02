
using Duende.IdentityServer.Models;

public class Config
{
    public static ApiScope[] ApiScopes =>
    [
        new ApiScope("scope1", "Scope 1"),
        new ApiScope("scope2", "Scope 2")
    ];
    public static IdentityResource[] IdentityResources =>
    [
        new IdentityResources.OpenId(),
        new IdentityResources.Profile(),
        new IdentityResource("scope1", "Scope 1", new[] { "scope1" }),
        new IdentityResource("scope2", "Scope 2", new[] { "scope2" })
    ];
    public static Client[] Clients =>
    [
        new Client
        {
            ClientId = "step-up",
            ClientName = "Step Up Client",
            AllowedGrantTypes = GrantTypes.Code,
            RequirePkce = true,
            RequireClientSecret = true,
            ClientSecrets =
            {
                new Secret("secret".Sha256())
            },
            RedirectUris = { "https://localhost:7002/signin-oidc" },
            PostLogoutRedirectUris = { "https://localhost:7002/signout-callback-oidc" },
            AllowedScopes =
            {
                "openid",
                "profile",
                "scope1",
                "scope2"
            },
            AllowOfflineAccess = true,
            AccessTokenLifetime = 3600,
            IdentityTokenLifetime = 300,
        }
    ];
}