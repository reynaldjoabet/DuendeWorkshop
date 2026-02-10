using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Logging;
using Duende.IdentityServer.Configuration; // types like OidcProvider
using Duende.IdentityServer.Stores; // IIdentityProviderStore
using Duende.IdentityServer.Hosting.DynamicProviders;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Duende.IdentityServer.Models;
using Microsoft.IdentityModel.Tokens;

public class DynamicOptions : ConfigureAuthenticationOptions<OpenIdConnectOptions, OidcProvider>
{
    private readonly ILogger<DynamicOptions> _logger;

    public DynamicOptions(IHttpContextAccessor httpContextAccessor, ILogger<DynamicOptions> logger)
        : base(httpContextAccessor, logger)
    {
        _logger = logger;
    }

    protected override void Configure(ConfigureAuthenticationContext<OpenIdConnectOptions, OidcProvider> context)
    {
        var provider = context.IdentityProvider;
        var options = context.AuthenticationOptions;

        options.SignInScheme = "Cookies";
        options.Authority = provider.Authority;
        options.ClientId = provider.ClientId;
        options.ClientSecret = provider.ClientSecret; // ensure secure storage in production
        options.CallbackPath = $"/signin-{provider.Scheme}";
        options.ResponseType = OpenIdConnectResponseType.Code;
        options.CallbackPath = $"/federation/{context.IdentityProvider.Scheme}/signin";
        options.ResponseType = "code";
        options.SaveTokens = true;

        options.Scope.Clear();
        options.Scope.Add("openid");

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = provider.Authority
        };
        // map scopes, claims mapping, etc. as needed

        _logger.LogInformation("Configured OIDC provider {Scheme} with Authority {Authority}", provider.Scheme, provider.Authority);


    }
}
