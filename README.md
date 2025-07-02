# DuendeWorkshop


# OpenIDConnectWebClientCore
OpenID Connect Implict flow sample using ASP.NET Core using .NETCore 1.1.0 framework.

 1. [Nuget Packages](#nuget-packages)
 1. [Code needed](#code-needed)
 1. [Configure SSL/TLS Port on IIS Express manually](#configure-ssltls-port-on-iis-express-manually)

---
## Nuget Packages
You will need to include the following Nuget packages:

 * Microsoft.AspNetCore.Authentication.OpenIdConnect
 * Microsoft.AspNetCore.Authentication.Cookies

---
## Code needed
You need to configure authentication in **Startup.cs** method **public void ConfigureServices(IServiceCollection services)** by adding
```cs
    services
        .AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
        })
        .AddCookie()
        .AddOpenIdConnect(options =>
        {
            options.ClientId = "MZxDS_9hY64cva_-V9eV";
            options.ClientSecret = "secret";
            options.Authority = "https://idp-uat.collectorbank.se/";
            options.ResponseType = OpenIdConnectResponseType.Code;
            options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.Events.OnRedirectToIdentityProvider = ctx => 
              // This is needed if you want to controll the authentication method and ui local that is used, per login request
            {
                ctx.ProtocolMessage.AcrValues = "urn:collectorbank:ac:method:nbid"; // Set desired login method
                ctx.ProtocolMessage.UiLocales = "sv nb"; // And desired language
                return Task.CompletedTask;
            };
        });
```

Then you need to activate Authentication aswell. This is done in **Startup.cs** method **public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)**
```c
    app.UseAuthentication();
```

If LoginHint is not specified then the default authentication method for the specified ClientId will be used.  
If UiLocales is not specified then the default local for the authentication method will be used.

---
## Configure SSL/TLS Port on IIS Express manually
The port used for the example are 45000.  
If SSL/TLS is not setup on that port you can configure it manually.

1. Open up an elevated Command Prompt (i.e. run Command Prompt as administrator)
1. Type command> netsh http show sslcert
1. Copy the certhash and appid of an existing entry
1. Copy/Type command> netsh http add sslcert ipport=0.0.0.0:45000 certhash=<certhash> appid=<appid>
   where you replace certhash and appid with the ones from an existing entry
   Example> netsh http add sslcert ipport=0.0.0.0:45000 certhash=241c2e7bcc16c2d772ac9a0e69ccfb36d45b95b9 appid={21d22dcd-d05b-4349-9bf9-9cdd44b2b74a}
---


```c#
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Spid.Cie.OIDC.AspNetCore.Configuration;
using Spid.Cie.OIDC.AspNetCore.Enums;
using Spid.Cie.OIDC.AspNetCore.Models;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Spid.Cie.OIDC.AspNetCore.Services;

class IdentityProvidersHandler : IIdentityProvidersHandler
{
    readonly ITrustChainManager _trustChainManager;
    readonly IOptionsMonitor<SpidCieOptions> _options;
    readonly IIdentityProvidersRetriever _idpRetriever;
    readonly ILogger<IdentityProvidersHandler> _logger;

    public IdentityProvidersHandler(IOptionsMonitor<SpidCieOptions> options, IIdentityProvidersRetriever idpRetriever,
                                    ITrustChainManager trustChainManager, ILogger<IdentityProvidersHandler> logger)
    {
        _logger = logger;
        _options = options;
        _idpRetriever = idpRetriever;
        _trustChainManager = trustChainManager;
    }

    public async Task<IEnumerable<IdentityProvider>> GetIdentityProviders()
    {
        List<IdentityProvider?> result = new();

        var idpUrls = _options.CurrentValue.CieOPs.Union(await _idpRetriever.GetCieIdentityProviders()).Select(ip => new
        {
            Type = IdentityProviderTypes.CIE,
            Url = ip
        }).Union(_options.CurrentValue.SpidOPs.Union(await _idpRetriever.GetSpidIdentityProviders()).Select(ip => new
        {
            Type = IdentityProviderTypes.SPID,
            Url = ip
        })).ToList();

        foreach (var idp in idpUrls)
        {
            var idpConf = await _trustChainManager.BuildTrustChain(idp.Url);

            if (idpConf != null)
                result.Add(idp.Type == IdentityProviderTypes.CIE ? CreateIdentityProvider<CieIdentityProvider>(idpConf) :
                            CreateIdentityProvider<SpidIdentityProvider>(idpConf));
        }

        return result.Where(r => r != default).ToList()!;
    }

    static T? CreateIdentityProvider<T>(OPEntityConfiguration conf)
        where T : IdentityProvider
    {
        return conf == default ? default :
            typeof(T).Equals(typeof(SpidIdentityProvider)) ?
            new SpidIdentityProvider()
            {
                EntityConfiguration = conf,
                Uri = conf.Subject ?? string.Empty,
                OrganizationLogoUrl = conf.Metadata.OpenIdProvider.AdditionalData.TryGetValue("logo_uri", out object? spidLogoUri) ? spidLogoUri as string ?? string.Empty : string.Empty,
                OrganizationName = conf.Metadata.OpenIdProvider.AdditionalData.TryGetValue("organization_name", out object? spidOrganizationName) ? spidOrganizationName as string ?? string.Empty : string.Empty,
                SupportedAcrValues = conf.Metadata.OpenIdProvider.AcrValuesSupported.ToList(),
            } as T :
            typeof(T).Equals(typeof(CieIdentityProvider)) ?
            new CieIdentityProvider()
            {
                EntityConfiguration = conf,
                Uri = conf.Subject ?? string.Empty,
                OrganizationLogoUrl = conf.Metadata.OpenIdProvider.AdditionalData.TryGetValue("logo_uri", out object? cieLogoUri) ? cieLogoUri as string ?? string.Empty : string.Empty,
                OrganizationName = conf.Metadata.OpenIdProvider.AdditionalData.TryGetValue("organization_name", out object? cieOrganizationName) ? cieOrganizationName as string ?? string.Empty : string.Empty,
                SupportedAcrValues = conf.Metadata.OpenIdProvider.AcrValuesSupported.ToList(),
            } as T : default;
    }

    
}
```


```c#
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Spid.Cie.OIDC.AspNetCore.Configuration;
using Spid.Cie.OIDC.AspNetCore.Enums;
using Spid.Cie.OIDC.AspNetCore.Helpers;
using Spid.Cie.OIDC.AspNetCore.Models;
using Spid.Cie.OIDC.AspNetCore.Resources;
using Spid.Cie.OIDC.AspNetCore.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Spid.Cie.OIDC.AspNetCore.Events;

internal class SpidCieEvents : OpenIdConnectEvents
{
    readonly ICryptoService _cryptoService;
    readonly IAggregatorsHandler _aggHandler;
    readonly IRelyingPartySelector _rpSelector;
    readonly IIdentityProviderSelector _idpSelector;
    readonly IOptionsMonitor<SpidCieOptions> _options;
    readonly IHttpContextAccessor _httpContextAccessor;
    readonly ITokenValidationParametersRetriever _tokenValidationParametersRetriever;

    public SpidCieEvents(IOptionsMonitor<SpidCieOptions> options, IIdentityProviderSelector idpSelector, IRelyingPartySelector rpSelector, ICryptoService cryptoService,
                            IAggregatorsHandler aggHandler, ITokenValidationParametersRetriever tokenValidationParametersRetriever, IHttpContextAccessor httpContextAccessor)
    {
        _options = options;
        _rpSelector = rpSelector;
        _aggHandler = aggHandler;
        _idpSelector = idpSelector;
        _httpContextAccessor = httpContextAccessor;
        _tokenValidationParametersRetriever = tokenValidationParametersRetriever;
        _cryptoService = cryptoService;
    }


    public override async Task RedirectToIdentityProvider(RedirectContext context)
    {
        var identityProvider = await _idpSelector.GetSelectedIdentityProvider();

        Throw<Exception>.If(identityProvider is null, ErrorLocalization.IdentityProviderNotFound);

        var relyingParty = await _rpSelector.GetSelectedRelyingParty();

        if (relyingParty == default)
        {
            var aggregators = await _aggHandler.GetAggregators();
            var uri = new Uri(UriHelper.GetEncodedUrl(_httpContextAccessor.HttpContext.Request))
                        .GetLeftPart(UriPartial.Path)
                        .Replace(SpidCieConst.JsonEntityConfigurationPath, "")
                        .Replace(SpidCieConst.EntityConfigurationPath, "")
                        .Replace(SpidCieConst.CallbackPath, "")
                        .Replace(SpidCieConst.SignedOutCallbackPath, "")
                        .Replace(SpidCieConst.RemoteSignOutPath, "")
                        .EnsureTrailingSlash();

            relyingParty = aggregators.SelectMany(a => a.RelyingParties)
                            .OrderByDescending(r => r.Id.Length)
                            .FirstOrDefault(r => uri.StartsWith(r.Id.EnsureTrailingSlash(), StringComparison.OrdinalIgnoreCase));
        }

        Throw<Exception>.If(relyingParty is null, ErrorLocalization.RelyingPartyNotFound);

        context.ProtocolMessage.AuthorizationEndpoint = identityProvider?.EntityConfiguration?.Metadata?.OpenIdProvider?.AuthorizationEndpoint!;
        context.ProtocolMessage.IssuerAddress = identityProvider?.EntityConfiguration?.Metadata?.OpenIdProvider?.AuthorizationEndpoint!;
        context.ProtocolMessage.TokenEndpoint = identityProvider?.EntityConfiguration?.Metadata?.OpenIdProvider?.TokenEndpoint!;
        context.ProtocolMessage.ClientId = relyingParty!.Id;
        context.ProtocolMessage.RedirectUri = $"{relyingParty!.Id.RemoveTrailingSlash()}{SpidCieConst.CallbackPath}";
        context.ProtocolMessage.AcrValues = identityProvider.GetAcrValue(relyingParty.SecurityLevel);

        if (_options.CurrentValue.RequestRefreshToken)
            context.ProtocolMessage.Scope += $" {SpidCieConst.OfflineScope}";

        context.Properties.Items[SpidCieConst.IdPSelectorKey] = identityProvider.Uri;
        context.Properties.Items[SpidCieConst.RPSelectorKey] = relyingParty.Id;

        await base.RedirectToIdentityProvider(context);
    }

    public virtual async Task PostStateCreated(PostStateCreatedContext context)
    {
        var identityProvider = await _idpSelector.GetSelectedIdentityProvider();

        Throw<Exception>.If(identityProvider is null, ErrorLocalization.IdentityProviderNotFound);

        var relyingParty = await _rpSelector.GetSelectedRelyingParty();

        if (relyingParty == default)
        {
            var aggregators = await _aggHandler.GetAggregators();
            var uri = new Uri(UriHelper.GetEncodedUrl(_httpContextAccessor.HttpContext.Request))
                        .GetLeftPart(UriPartial.Path)
                        .Replace(SpidCieConst.JsonEntityConfigurationPath, "")
                        .Replace(SpidCieConst.EntityConfigurationPath, "")
                        .Replace(SpidCieConst.CallbackPath, "")
                        .Replace(SpidCieConst.SignedOutCallbackPath, "")
                        .Replace(SpidCieConst.RemoteSignOutPath, "")
                        .EnsureTrailingSlash();

            relyingParty = aggregators.SelectMany(a => a.RelyingParties)
                            .OrderByDescending(r => r.Id.Length)
                            .FirstOrDefault(r => uri.StartsWith(r.Id.EnsureTrailingSlash(), StringComparison.OrdinalIgnoreCase));
        }

        Throw<Exception>.If(relyingParty is null, ErrorLocalization.RelyingPartyNotFound);
        Throw<Exception>.If(relyingParty!.OpenIdCoreCertificates is null || relyingParty!.OpenIdCoreCertificates.Count() == 0,
                "No OpenIdCore certificates were found in the currently selected RelyingParty");

        var certificate = relyingParty!.OpenIdCoreCertificates!.FirstOrDefault(occ => occ.KeyUsage == KeyUsageTypes.Signature)!;

        context.ProtocolMessage.SetParameter(SpidCieConst.RequestParameter,
            GenerateJWTRequest(identityProvider!, relyingParty!, context.ProtocolMessage, certificate.Certificate!));
    }

    string GenerateJWTRequest(IdentityProvider idp, RelyingParty relyingParty, OpenIdConnectMessage protocolMessage, X509Certificate2 certificate)
    {
        return _cryptoService.CreateJWT(certificate!,
            new Dictionary<string, object>() {
                    { SpidCieConst.Iss, protocolMessage.ClientId },
                    //{ SpidCieConst.Sub, protocolMessage.ClientId },
                    { SpidCieConst.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds() },
                    { SpidCieConst.Exp, DateTimeOffset.UtcNow.AddMinutes(SpidCieConst.EntityConfigurationExpirationInMinutes).ToUnixTimeSeconds() },
                    { SpidCieConst.Aud, new string[] { idp.EntityConfiguration.Issuer, idp.EntityConfiguration.Metadata.OpenIdProvider!.AuthorizationEndpoint } },
                    { SpidCieConst.ClientId, protocolMessage.ClientId },
                    { SpidCieConst.ResponseTypeParameter, protocolMessage.ResponseType },
                    { SpidCieConst.Scope, protocolMessage.Scope },
                    { SpidCieConst.CodeChallenge, protocolMessage.GetParameter(SpidCieConst.CodeChallenge) },
                    { SpidCieConst.CodeChallengeMethod, protocolMessage.GetParameter(SpidCieConst.CodeChallengeMethod) },
                    { SpidCieConst.Nonce, protocolMessage.Nonce },
                    { SpidCieConst.PromptParameter, protocolMessage.Prompt },
                    { SpidCieConst.RedirectUri, protocolMessage.RedirectUri },
                    { SpidCieConst.AcrValues, protocolMessage.AcrValues },
                    { SpidCieConst.State, protocolMessage.State },
                    { SpidCieConst.Claims, new { userinfo = idp.FilterRequestedClaims(relyingParty.RequestedClaims).ToDictionary(c => c, c => (object?)null) } }
            });

    }

    public override async Task MessageReceived(MessageReceivedContext context)
    {
        if (!string.IsNullOrWhiteSpace(context.ProtocolMessage!.Error))
        {
            var ex = new Exception(context.ProtocolMessage.ErrorDescription ?? context.ProtocolMessage.Error);

            ex.Data.Add(nameof(context.ProtocolMessage.Error), context.ProtocolMessage.Error);
            ex.Data.Add(nameof(context.ProtocolMessage.ErrorDescription), context.ProtocolMessage.ErrorDescription);
            ex.Data.Add(nameof(context.ProtocolMessage.ErrorUri), context.ProtocolMessage.ErrorUri);
            context.Fail(ex);
        }
        else
        {
            context.Properties!.Items.TryGetValue(SpidCieConst.IdPSelectorKey, out var provider);

            if (!string.IsNullOrWhiteSpace(provider))
                _httpContextAccessor.HttpContext!.Items.Add(SpidCieConst.IdPSelectorKey, provider);

            context.Properties!.Items.TryGetValue(SpidCieConst.RPSelectorKey, out var clientId);

            if (!string.IsNullOrWhiteSpace(clientId))
            {
                context.Options.ClientId = clientId;
                _httpContextAccessor.HttpContext!.Items.Add(SpidCieConst.RPSelectorKey, clientId);
            }

            context.Options.TokenValidationParameters = await _tokenValidationParametersRetriever.RetrieveTokenValidationParameter();
        }

        await base.MessageReceived(context);
    }

    public override async Task AuthorizationCodeReceived(AuthorizationCodeReceivedContext context)
    {
        var identityProvider = await _idpSelector.GetSelectedIdentityProvider();

        Throw<Exception>.If(identityProvider is null, ErrorLocalization.IdentityProviderNotFound);

        var relyingParty = await _rpSelector.GetSelectedRelyingParty();

        if (relyingParty == default)
        {
            var aggregators = await _aggHandler.GetAggregators();
            var uri = new Uri(UriHelper.GetEncodedUrl(_httpContextAccessor.HttpContext.Request))
                        .GetLeftPart(UriPartial.Path)
                        .Replace(SpidCieConst.JsonEntityConfigurationPath, "")
                        .Replace(SpidCieConst.EntityConfigurationPath, "")
                        .Replace(SpidCieConst.CallbackPath, "")
                        .Replace(SpidCieConst.SignedOutCallbackPath, "")
                        .Replace(SpidCieConst.RemoteSignOutPath, "")
                        .EnsureTrailingSlash();

            relyingParty = aggregators.SelectMany(a => a.RelyingParties)
                            .OrderByDescending(r => r.Id.Length)
                            .FirstOrDefault(r => uri.StartsWith(r.Id.EnsureTrailingSlash(), StringComparison.OrdinalIgnoreCase));
        }

        Throw<Exception>.If(relyingParty is null, ErrorLocalization.RelyingPartyNotFound);
        Throw<Exception>.If(relyingParty!.OpenIdCoreCertificates is null || relyingParty!.OpenIdCoreCertificates.Count() == 0,
                "No OpenIdCore Keys were found in the currently selected RelyingParty");

        var certificate = relyingParty!.OpenIdCoreCertificates!.FirstOrDefault(occ => occ.KeyUsage == KeyUsageTypes.Signature)!;

        Throw<Exception>.If(context.TokenEndpointRequest is null, $"No Token Endpoint Request found in the current context");

        context.TokenEndpointRequest!.ClientAssertionType = SpidCieConst.ClientAssertionTypeValue;
        context.TokenEndpointRequest!.ClientAssertion = _cryptoService.CreateClientAssertion(identityProvider!.EntityConfiguration.Metadata.OpenIdProvider!.TokenEndpoint!,
            relyingParty.Id!, certificate.Certificate!);

        await base.AuthorizationCodeReceived(context);
    }
}
```


```c#
### Configure OpenID Connect Middleware

To enable authentication in your ASP.NET Core application, use the OpenID Connect (OIDC) middleware.
Go to the `ConfigureServices` method of your `Startup` class. To add the authentication services, call the `AddAuthentication` method. To enable cookie authentication, call the `AddCookie` method.

Next, configure the OIDC authentication handler. Add a call to `AddOpenIdConnect`. Configure the necessary parameters, such as `ClientId`, `ClientSecret`, `ResponseType`, and not least the `Authority`. The latter is used by the middleware to get the metadata describing the relevant endpoints, the signing keys etc.

The OIDC middleware requests both the `openid` and `profile` scopes by default, but note that Criipto Verify by nature returns only the information derived from the underlying e-ID service. Changing the scopes does not affect the amount and nature of information delivered from the user information endpoint.

```cs
// Startup.cs

public void ConfigureServices(IServiceCollection services)
{
    services.Configure<CookiePolicyOptions>(options =>
    {
        // This lambda determines whether user consent for non-essential cookies is needed for a given request.
        options.CheckConsentNeeded = context => true;
        options.MinimumSameSitePolicy = SameSiteMode.None;
    });

    services.AddAuthentication(options => {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie()
    .AddOpenIdConnect(options => {
        options.ClientId = Configuration["Criipto:ClientId"]; // ClientID from application registration
        options.ClientSecret = Configuration["Criipto:ClientSecret"]; // Client from application registration
        options.Authority = $"https://{Configuration["Criipto:Domain"]}/"; // Domain from application registration
        options.ResponseType = "code";

        // The next to settings must match the Callback URLs in Criipto Verify
        options.CallbackPath = new PathString("/callback"); 
        options.SignedOutCallbackPath = new PathString("/signout");

        // Hook up an event handler to set the acr_value of the authorize request
        // In a real world implementation this is probably a bit more flexible
        options.Events = new OpenIdConnectEvents() {
            OnRedirectToIdentityProvider = context => {
                context.ProtocolMessage.AcrValues = context.Request.Query["loginmethod"];
                return Task.FromResult(0);
            }
        };
    });

    services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_2);
}
```

_Note_ that the above code dynamically sets the `AcrValues` by picking it from the query string. In the general case, this may, of course, be set in other ways. Just note that it is dynamically set at the time of the actual login.

<a name="loginmethod"></a>

### Choosing the specific login method

{% include snippets/login-methods.md %}

### Enable the OpenID Connect middleware

Next, add the authentication middleware. In the `Configure` method of the `Startup` class, call the `UseAuthentication` method.

```csharp
// Startup.cs

public void Configure(IApplicationBuilder app, IHostingEnvironment env)
{
    if (env.IsDevelopment())
    {
        app.UseDeveloperExceptionPage();
    }
    else
    {
        app.UseExceptionHandler("/Home/Error");
        app.UseHsts();
    }

    app.UseHttpsRedirection();
    app.UseStaticFiles();
    app.UseCookiePolicy();

    app.UseAuthentication();

    app.UseMvc(routes =>
    {
        routes.MapRoute(
            name: "default",
            template: "{controller=Home}/{action=Index}/{id?}");
    });
}
```

<a name="trigger"></a>
## Trigger Login and Logout in Your Application

After the middleware for performing the authentication is wired up, the next step is to perform the actual authentication.

### Protected resources trigger login

One way to trigger the authentication flow is to tag routes in ASP.NET MVC with the `Authorize`. This is a way of telling the framework to only allow requests from authenticated users.

```csharp
[Authorize] // If not already authenticated, this kicks off the process
public IActionResult Protected()
{
    return View();
}
```

Note that you may plug in your own Authorization handlers derived from `Microsoft.AspNetCore.Authorization.AuthorizationHandler<TRequirement>` to add additional guards beyond just authentication.

### Explicit logout

Logout requires both terminating the local session by removing the cookies as well as telling Criipto Verify that the session is over.

```csharp
public async Task Logout()
{
    // Call the server to terminate the session
    await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);

    // Remove authnetication cookies
    await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
}
``` 


```c#
var userAgent = n.Request.Headers["User-Agent"].ToString().ToLower();
if (userAgent.Contains("dingtalk"))
{
    n.ProtocolMessage.AcrValues = "idp:DingTalk";
}
if (n.HttpContext.Session.Get("sso_login_user") != null)
{
    n.ProtocolMessage.AcrValues = "idp:Weixin"; //此处设置默认的第三方登录类型
}
n.ProtocolMessage.AcrValues = "idp:DingTalk";

```


