using Duende.IdentityServer.Configuration; // OidcProvider type lives here
using Duende.IdentityServer.Hosting.DynamicProviders;
using Duende.IdentityServer.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;

public class ConfigureOidcOptions : ConfigureAuthenticationOptions<OpenIdConnectOptions, OidcProvider>
{
    private readonly ILogger<ConfigureOidcOptions> _logger;

    public ConfigureOidcOptions(IHttpContextAccessor httpContextAccessor, ILogger<ConfigureOidcOptions> logger)
        : base(httpContextAccessor, logger)
    {
        _logger = logger;
    }

    protected override void Configure(ConfigureAuthenticationContext<OpenIdConnectOptions, OidcProvider> context)
    {
        var provider = context.IdentityProvider;
        var options = context.AuthenticationOptions;

        // Required: runtime scheme name must match the IdentityProvider.Scheme
        // Sign-in scheme for the OIDC handler to use when creating local identities
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;

        // Map the provider fields to the OpenIdConnect options
        options.Authority = provider.Authority;
        options.ClientId = provider.ClientId;
        options.ClientSecret = provider.ClientSecret; // secure secrets in production
        options.ResponseType = OpenIdConnectResponseType.Code;
        
        // **Important: set a unique callback path per provider
        // OidcProvider doesn't have CallbackPath, so we construct it from the scheme
        var callbackPath = $"/federation/{provider.Scheme}/signin";
        options.CallbackPath = callbackPath; // eg "/federation/provider1/signin"

        // Map scope(s)
        if (!string.IsNullOrEmpty(provider.Scope))
        {
            foreach (var s in provider.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                if (!options.Scope.Contains(s))
                    options.Scope.Add(s);
            }
        }
        else
        {
            options.Scope.Add("openid");
            options.Scope.Add("profile");
        }

        // Map other common settings
        options.SaveTokens = true;

        // Token validation parameters example (you may tune as needed)
        options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
        {
            NameClaimType = "name",
            RoleClaimType = "role"
        };

        // Events: optional for logging / mapping
        options.Events = new OpenIdConnectEvents
        {
            OnTokenValidated = ctx =>
            {
                _logger.LogInformation("Token validated for scheme {scheme}", provider.Scheme);
                return System.Threading.Tasks.Task.CompletedTask;
            },
            OnAuthenticationFailed = ctx =>
            {
                _logger.LogError(ctx.Exception, "Authentication failed for scheme {scheme}", provider.Scheme);
                return System.Threading.Tasks.Task.CompletedTask;
            }
        };
    }
}
