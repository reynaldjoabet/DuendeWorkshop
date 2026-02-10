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

Your App using Duende as IdP
```c#
services.AddAuthentication(options =>
{
    options.DefaultScheme = "Cookies";            // local session
    options.DefaultChallengeScheme = "oidc";      // go to Duende for sign-in
})
.AddCookie("Cookies")
.AddOpenIdConnect("oidc", options =>
{
    options.Authority = "https://idp.example.com";
    options.ClientId = "webapp";
    options.ClientSecret = "secret";
    options.ResponseType = "code";
    options.SaveTokens = true;                    // store tokens in auth session if needed
});
```

Duende federating to an external IdP
```c#
services.AddAuthentication()
    // Duende’s own login cookie for interactive users
    .AddCookie("idsrv")

    // Temp cookie used during external sign-in dance
    .AddCookie("idsrv.external")

    // External provider (Duende acting as an OIDC client)
    .AddOpenIdConnect("azuread", options =>
    {
        options.Authority = "https://login.microsoftonline.com/{tenant}";
        options.ClientId = "{client-id}";
        options.ClientSecret = "{secret}";
        options.ResponseType = "code";
        options.CallbackPath = "/signin-azuread";

        // Map incoming claims, etc.
        options.Events = new OpenIdConnectEvents
        {
            OnTokenValidated = ctx =>
            {
                // Optionally transform claims before Duende creates/updates its cookie
                return Task.CompletedTask;
            }
        };
    });
```

An authentication ticket is an object that represents a user’s authenticated identity plus metadata about how they were authenticated.

By default, the CookieAuthenticationHandler works like this:
- On sign-in, it creates an `AuthenticationTicket`.
It serializes the ticket (using - TicketSerializer) into a compact, encrypted blob.
- That blob goes directly into the authentication cookie.
On each request, the handler:
Reads the cookie,
- Decrypts/deserializes the ticket,
Restores the user’s ClaimsPrincipal.
- This means the entire ticket (claims, properties) lives inside the cookie.

### SessionStore
The SessionStore is an optional abstraction you can plug into the cookie handler. Instead of putting the full authentication ticket into the cookie, you can:
Store the ticket server-side (e.g., in memory, distributed cache, or database).
Put only a session identifier into the cookie.
That way, the cookie itself doesn’t carry the full claims payload, just a key to look it up.

### Why Use It?
- Reduce cookie size: If you have many claims or store tokens (SaveTokens = true), the cookie can become very large.
- Centralize session state: Useful in load-balanced / distributed setups, where you want session revocation or introspection.
- Better security control: You can expire, update, or revoke sessions centrally without waiting for the cookie lifetime to elapse.

```c#
services.AddAuthentication("Cookies")
    .AddCookie("Cookies", options =>
    {
        options.SessionStore = new MyTicketStore();
    });
```

`await HttpContext.SignInAsync("Cookies", principal, props);`

- the `CookieAuthenticationHandler`:
Creates an AuthenticationTicket.
Serializes it into a byte array (using TicketSerializer).
- Passes it to the Data Protection system for encryption and signing.
Base64-encodes the protected blob and writes it into the Set-Cookie header


```c#
services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(@"\\server\share\keys"))
    .ProtectKeysWithDpapiNG();
```
Or use Redis, SQL Server, or Azure KeyVault for key storage.

The cookie is encrypted (AES-256) and signed (HMACSHA256) using ASP.NET Core’s Data Protection system. The app (or cluster of apps, if you configure shared key storage) manages keys automatically, rotating them periodically.


### Data Protection System
ASP.NET Core uses the Microsoft.AspNetCore.DataProtection stack to encrypt cookies (and other things like antiforgery tokens).
- Algorithms (by default):
  - Encryption: AES-256-CBC
  - Validation: HMACSHA256
(wrapped in an "Authenticated Encryption" mechanism)
- Keys:
  - Stored in a key ring (usually on disk in App_Data, %LOCALAPPDATA%, or wherever you configure).
  - Each key has a creation date, activation date, expiration date.
Keys rotate automatically every 90 days (by default).
- Key persistence:
  - In single-server apps, the default local file system is fine.
  - In multi-server/load-balanced setups, you must configure a shared key store (e.g., database, Redis, Azure Blob/KeyVault) so all servers can read/write the same keys.

### Reading the Cookie
- On the next request:
The cookie handler takes the cookie value.
- Passes it to the Data Protection system.
- Data Protection:
Validates the HMAC signature.
- Decrypts the payload using the current or past valid key.
The payload is deserialized back into the AuthenticationTicket (→ ClaimsPrincipal).


`TokenExchangeGrantValidator`

## Extension Grants
- OAuth defines an extensibility point called extension grants.
- Extension grants allow adding support for non-standard token issuance scenarios, e.g.
  - token transformation
     - SAML to JWT, or Windows to JWT
  - delegation or impersonation
  - federation
  - encapsulating custom input parameters
You can add support for additional grant types by implementing the IExtensionGrantValidator interface.

## Token Exchange
The OAuth Token Exchange specification (RFC 8693) describes a general purpose mechanism for translating between token types. Common use cases are creating tokens for impersonation and delegation purposes - but it is not limited to that.
You can leverage the extension grant feature to implement your preferred token exchange logic.
Some of the logic is boilerplate:
read and validate incoming protocol parameters
- validate incoming token
  - using the built-in token validator if the token was issued by the same token service
  - using a token type specific library if the token is coming from a trusted (but different) token service
- read contents of token to apply custom logic/authorization if needed
- create response
Here’s a simple implementation of the above steps:

```c#
public class TokenExchangeGrantValidator : IExtensionGrantValidator
{
    private readonly ITokenValidator _validator;

    public TokenExchangeGrantValidator(ITokenValidator validator)
    {
        _validator = validator;
    }

    // register for urn:ietf:params:oauth:grant-type:token-exchange
    public string GrantType => OidcConstants.GrantTypes.TokenExchange;

    public async Task ValidateAsync(ExtensionGrantValidationContext context)
    {
        // default response is error
        context.Result = new GrantValidationResult(TokenRequestErrors.InvalidRequest);

        // the spec allows for various token types, most commonly you return an access token
        var customResponse = new Dictionary<string, object>
        {
            { OidcConstants.TokenResponse.IssuedTokenType, OidcConstants.TokenTypeIdentifiers.AccessToken }
        };

        // read the incoming token
        var subjectToken = context.Request.Raw.Get(OidcConstants.TokenRequest.SubjectToken);

        // and the token type
        var subjectTokenType = context.Request.Raw.Get(OidcConstants.TokenRequest.SubjectTokenType);

        // mandatory parameters
        if (string.IsNullOrWhiteSpace(subjectToken))
        {
            return;
        }

        // for our impersonation/delegation scenario we require an access token
        if (!string.Equals(subjectTokenType, OidcConstants.TokenTypeIdentifiers.AccessToken))
        {
            return;
        }

        // validate the incoming access token with the built-in token validator
        var validationResult = await _validator.ValidateAccessTokenAsync(subjectToken);
        if (validationResult.IsError)
        {
            return;
        }

        // these are two values you typically care about
        var sub = validationResult.Claims.First(c => c.Type == JwtClaimTypes.Subject).Value;
        var clientId = validationResult.Claims.First(c => c.Type == JwtClaimTypes.ClientId).Value;

        // add any custom logic here (if needed)

        // create response
    }
}
```

You then register your grant validator with DI:

```c#
idsvrBuilder.AddExtensionGrantValidator<TokenExchangeGrantValidator>();
```

And configure your client to be able to use it:

`client.AllowedGrantTypes = { OidcConstants.GrantTypes.TokenExchange };`


```cshtml
@inject Microsoft.Extensions.Configuration.IConfiguration Config
@{
    // Optional build/version for cache-busting
    var build = Config["Build:Version"] ?? DateTime.UtcNow.Ticks.ToString();
}
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Portal</title>

  <script>
    // Must be defined BEFORE loading dojo.js
    // Docs: dojoConfig + AMD loader config. 
    // packages = array of { name, location } (location can be absolute) 
    // deps = modules to load immediately after the loader boots
    var dojoConfig = {
      async: true,
      baseUrl: "/",                        // where relative packages resolve from
      cacheBust: "@build",                 // optional: force fresh loads per deploy
      packages: [
        // Host (“shell”) package compiled as AMD
        { name: "host",    location: "/static/host" },

        // Each microfrontend as its own AMD package
        { name: "catalog", location: "@Config["Remotes:CatalogAmd"]" }, // e.g. https://cdn.example.com/catalog
        { name: "account", location: "@Config["Remotes:AccountAmd"]" }
      ],
      // Optional: map/paths if you need to pin third-party libs by “package” name
      paths: {
        // bare specifiers (no .js extension)
        "react": "/lib/react/18.3.0/react.production.min",
        "react-dom": "/lib/react-dom/18.3.0/react-dom.production.min"
      },
      deps: ["host/main"] // boot your host after loader initializes
    };
  </script>

  <!-- Dojo AMD loader -->
  <script src="/lib/dojo/dojo.js"></script>
</head>
<body>
  <div id="app-root"></div>
</body>
</html>
```

With the config above, your host can load each microfrontend by its `package name`:
```js
// host/main.js (AMD)
define([
  "dojo/domReady!",
  "catalog/Routes",  // resolved via dojoConfig.packages
  "account/Routes"
], function (_domReady, CatalogRoutes, AccountRoutes) {
  // mount routes / render into #app-root, etc.
});
```

packages items are `{ name, location }`. `location` can be relative to `baseUrl` or an `absolute` URL (handy for MFEs on a CDN)

Relative Path
A relative path gives the location of a file relative to your current working directory.

If you are in `/home/username/Documents`: `report.txt`

means `/home/username/Documents/report.txt`
`../Pictures/photo.jpg` means “go up one directory” → `/home/username/Pictures/photo.jpg`

- Depends on where you are currently located (your current working directory)

Absolute Path

An absolute path gives the complete location of a file or directory from the root of the filesystem.

It always starts from the root directory (the topmost level).
On Linux / macOS: `/home/username/Documents/report.txt`

`..` is also a relative path: means “the parent directory” of your current location.
So both . and .. are special relative path notations:

`.` → current directory
`..` → parent directory

```cshtml
@*<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">*@
    @*<title>@ViewBag.Title - My ASP.NET Application</title>*@
    <script>
        var dojoConfig = {
            async: true,
            waitSeconds: 0,
            packages: [
                { name: 'dojo', location: '@Url.Content("~/Script/dojoSRC/dojo")' },
                { name: 'dijit', location: '@Url.Content("~/Script/dojoSRC/dijit")' },
                { name: 'themes', location: '@Url.Content("~/Script/dojoSRC/dijit-themes")' },
            ]
        }
    </script>
    <script src="~/Scripts/dojoSRC/dojo/dojo.js"></script>
    @Styles.Render("~/Content/css")
    @Scripts.Render("~/bundles/modernizr")
@*</head>
<body>*@
    @*<div class="navbar navbar-inverse navbar-fixed-top">
        <div class="container">
            <div class="navbar-header">
                <button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-collapse" title="more options">
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                </button>
                @Html.ActionLink("Application name", "Index", "Home", new { area = "" }, new { @class = "navbar-brand" })
            </div>
            <div class="navbar-collapse collapse">
                <ul class="nav navbar-nav">
                    <li>@Html.ActionLink("Home", "Index", "Home")</li>
                    <li>@Html.ActionLink("About", "About", "Home")</li>
                    <li>@Html.ActionLink("Contact", "Contact", "Home")</li>
                </ul>
            </div>
        </div>
    </div>
    <div class="container body-content">
        @RenderBody()
        <hr />
        <footer>
            <p>&copy; @DateTime.Now.Year - My ASP.NET Application</p>
        </footer>
    </div>*@
    <script>
        require(["dijit/resgistry", "dojo/parser"], function (registry, parser) {
            parser.parse();
        })
    </script>
    @Scripts.Render("~/bundles/jquery")
    @Scripts.Render("~/bundles/bootstrap")
    @RenderSection("scripts", required: false)
@*</body>
</html>*@
```
<!-- Dojo AMD loader (load AFTER dojoConfig) -->
<script src="~/Scripts/dojoSRC/dojo/dojo.js"></script>

```c#

/// <summary>
/// Models the common data of API and identity resources.
/// </summary>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public abstract class Resource
{
    private string DebuggerDisplay => Name ?? $"{{{typeof(Resource)}}}";

    /// <summary>
    /// Indicates if this resource is enabled. Defaults to true.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// The unique name of the resource.
    /// </summary>
    public string Name { get; set; } = default!;

    /// <summary>
    /// Display name of the resource.
    /// </summary>
    public string? DisplayName { get; set; }
        
    /// <summary>
    /// Description of the resource.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Specifies whether this scope is shown in the discovery document. Defaults to true.
    /// </summary>
    public bool ShowInDiscoveryDocument { get; set; } = true;

    /// <summary>
    /// List of associated user claims that should be included when this resource is requested.
    /// </summary>
    public ICollection<string> UserClaims { get; set; } = new HashSet<string>();

    /// <summary>
    /// Gets or sets the custom properties for the resource.
    /// </summary>
    /// <value>
    /// The properties.
    /// </value>
    public IDictionary<string, string> Properties { get; set; } = new Dictionary<string, string>();
}
```

```c#
/// Models a user identity resource.
/// </summary>
[DebuggerDisplay("{" + nameof(DebuggerDisplay) + ",nq}")]
public class IdentityResource : Resource{

     /// <summary>
    /// Specifies whether the user can de-select the scope on the consent screen (if the consent screen wants to implement such a feature). Defaults to false.
    /// </summary>
    public bool Required { get; set; } = false;

    /// <summary>
    /// Specifies whether the consent screen will emphasize this scope (if the consent screen wants to implement such a feature). 
    /// Use this setting for sensitive or important scopes. Defaults to false.
    /// </summary>
    public bool Emphasize { get; set; } = false;

    /// <summary>
    /// Initializes a new instance of the <see cref="IdentityResource"/> class.
    /// </summary>
    /// <param name="name">The name.</param>
    /// <param name="displayName">The display name.</param>
    /// <param name="userClaims">List of associated user claims that should be included when this resource is requested.</param>
    /// <exception cref="System.ArgumentNullException">name</exception>
    /// <exception cref="System.ArgumentException">Must provide at least one claim type - claimTypes</exception>
    public IdentityResource(string name, string displayName, IEnumerable<string> userClaims)
    {
        if (name.IsMissing()) throw new ArgumentNullException(nameof(name));
        if (userClaims.IsNullOrEmpty()) throw new ArgumentException("Must provide at least one claim type", nameof(userClaims));

        Name = name;
        DisplayName = displayName;

        foreach(var type in userClaims)
        {
            UserClaims.Add(type);
        }
    }
}
```

```c#
// Summary:
//     Models access to an API scope
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public class ApiScope : Resource{

       //
    // Summary:
    //     Specifies whether the user can de-select the scope on the consent screen. Defaults
    //     to false.
    public bool Required { get; set; }

    //
    // Summary:
    //     Specifies whether the consent screen will emphasize this scope. Use this setting
    //     for sensitive or important scopes. Defaults to false.
    public bool Emphasize { get; set; }

      //
    // Summary:
    //     Initializes a new instance of the Duende.IdentityServer.Models.ApiScope class.
    //
    //
    // Parameters:
    //   name:
    //     The name.
    //
    //   userClaims:
    //     List of associated user claims that should be included when this resource is
    //     requested.
    public ApiScope(string name, IEnumerable<string> userClaims)
        : this(name, name, userClaims)
    {
    }
      //
    // Summary:
    //     Initializes a new instance of the Duende.IdentityServer.Models.ApiScope class.
    //
    //
    // Parameters:
    //   name:
    //     The name.
    //
    //   displayName:
    //     The display name.
    //
    //   userClaims:
    //     List of associated user claims that should be included when this resource is
    //     requested.
    //
    // Exceptions:
    //   T:System.ArgumentNullException:
    //     name
    public ApiScope(string name, string displayName, IEnumerable<string>? userClaims)
    {
        if (name.IsMissing())
        {
            throw new ArgumentNullException("name");
        }

        base.Name = name;
        base.DisplayName = displayName;
        if (userClaims.IsNullOrEmpty())
        {
            return;
        }

        foreach (string userClaim in userClaims)
        {
            base.UserClaims.Add(userClaim);
        }
    }
}

```


```c#
// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


#nullable enable

using Duende.IdentityModel;
using System.Linq;

namespace Duende.IdentityServer.Models;

/// <summary>
/// Convenience class that defines standard identity resources.
/// </summary>
public static class IdentityResources
{
    /// <summary>
    /// Models the standard openid scope
    /// </summary>
    /// <seealso cref="IdentityServer.Models.IdentityResource" />
    public class OpenId : IdentityResource
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="OpenId"/> class.
        /// </summary>
        public OpenId()
        {
            Name = IdentityServerConstants.StandardScopes.OpenId;
            DisplayName = "Your user identifier";
            Required = true;
            UserClaims.Add(JwtClaimTypes.Subject);
        }
    }

    /// <summary>
    /// Models the standard profile scope
    /// </summary>
    /// <seealso cref="IdentityServer.Models.IdentityResource" />
    public class Profile : IdentityResource
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Profile"/> class.
        /// </summary>
        public Profile()
        {
            Name = IdentityServerConstants.StandardScopes.Profile;
            DisplayName = "User profile";
            Description = "Your user profile information (first name, last name, etc.)";
            Emphasize = true;
            UserClaims = Constants.ScopeToClaimsMapping[IdentityServerConstants.StandardScopes.Profile].ToList();
        }
    }

    /// <summary>
    /// Models the standard email scope
    /// </summary>
    /// <seealso cref="IdentityServer.Models.IdentityResource" />
    public class Email : IdentityResource
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Email"/> class.
        /// </summary>
        public Email()
        {
            Name = IdentityServerConstants.StandardScopes.Email;
            DisplayName = "Your email address";
            Emphasize = true;
            UserClaims = (Constants.ScopeToClaimsMapping[IdentityServerConstants.StandardScopes.Email].ToList());
        }
    }

    /// <summary>
    /// Models the standard phone scope
    /// </summary>
    /// <seealso cref="IdentityServer.Models.IdentityResource" />
    public class Phone : IdentityResource
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Phone"/> class.
        /// </summary>
        public Phone()
        {
            Name = IdentityServerConstants.StandardScopes.Phone;
            DisplayName = "Your phone number";
            Emphasize = true;
            UserClaims = Constants.ScopeToClaimsMapping[IdentityServerConstants.StandardScopes.Phone].ToList();
        }
    }

    /// <summary>
    /// Models the standard address scope
    /// </summary>
    /// <seealso cref="IdentityServer.Models.IdentityResource" />
    public class Address : IdentityResource
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Address"/> class.
        /// </summary>
        public Address()
        {
            Name = IdentityServerConstants.StandardScopes.Address;
            DisplayName = "Your postal address";
            Emphasize = true;
            UserClaims = Constants.ScopeToClaimsMapping[IdentityServerConstants.StandardScopes.Address].ToList();
        }
    }
}

```
```c#
public static IEnumerable<ApiScope> GetApiScopes()
{
    return new List<ApiScope>
    {
        // invoice API specific scopes
        new ApiScope(name: "invoice.read",   displayName: "Reads your invoices."),
        new ApiScope(name: "invoice.pay",    displayName: "Pays your invoices."),

        // customer API specific scopes
        new ApiScope(name: "customer.read",    displayName: "Reads you customers information."),
        new ApiScope(name: "customer.contact", displayName: "Allows contacting one of your customers."),

        // shared scopes
        new ApiScope(name: "manage",    displayName: "Provides administrative access."),
        new ApiScope(name: "enumerate", displayName: "Allows enumerating data.")
    };
}

```

With `ApiResource` you can now create two logical APIs and their corresponding scopes:
```c#
public static readonly IEnumerable<ApiResource> GetApiResources()
{
    return new List<ApiResource>
    {
        new ApiResource("invoice", "Invoice API")
        {
            Scopes = { "invoice.read", "invoice.pay", "manage", "enumerate" }
        },

        new ApiResource("customer", "Customer API")
        {
            Scopes = { "customer.read", "customer.contact", "manage", "enumerate" }
        }
    };
}
```



Using the API resource grouping gives you the following additional features
- support for the JWT `aud` claim. The value(s) of the audience claim will be the name of the API resource(s)
- support for adding common user claims across all contained scopes
- support for introspection by assigning an API secret to the resource
- support for configuring the access token signing algorithm for the resource

Let’s have a look at some example access tokens for the above resource configuration.

Client requests: `invoice.read` and `invoice.pay`:

```json
    {
        "typ": "at+jwt"
    }.
    {
        "client_id": "client",
        "sub": "123",

        "aud": "invoice",
        "scope": "invoice.read invoice.pay"
    }
    ```
Client requests: `invoice.read` and `customer.read`:
```json
    {
        "typ": "at+jwt"
    }.
    {
        "client_id": "client",
        "sub": "123",

        "aud": [ "invoice", "customer" ],
        "scope": "invoice.read customer.read"
    }

 ```   

Client requests: `manage`:
```json
    {
        "typ": "at+jwt"
    }.
    {
        "client_id": "client",
        "sub": "123",

        "aud": [ "invoice", "customer" ],
        "scope": "manage"
    }
```     
## Adding User Claims

You can specify that an access token for an API resource (regardless of which scope is requested) should contain additional user claims.
```c#
var customerResource = new ApiResource("customer", "Customer API")
    {
        Scopes = { "customer.read", "customer.contact", "manage", "enumerate" },

        // additional claims to put into access token
        UserClaims =
        {
            "department_id",
            "sales_region"
        }
    }
```    
If a client now requested a scope belonging to the `customer` resource, the access token would contain the additional claims (if provided by your profile service).

```json
    {
        "typ": "at+jwt"
    }.
    {
        "client_id": "client",
        "sub": "123",

        "aud": [ "invoice", "customer" ],
        "scope": "invoice.read customer.read",

        "department_id": 5,
        "sales_region": "south"
    }

```

### Setting A Signing Algorithm

The following sample sets `PS256` as the required signing algorithm for the `invoices` API:
```c#
var invoiceApi = new ApiResource("invoice", "Invoice API")
    {
        Scopes = { "invoice.read", "invoice.pay", "manage", "enumerate" },

        AllowedAccessTokenSigningAlgorithms = { SecurityAlgorithms.RsaSsaPssSha256 }
    }
```        
## User Claims

User claims can be emitted in both identity and access tokens and in the userinfo endpoint. The central extensibility point to implement to emit claims is called the profile service. The profile service is responsible for both gathering claim data and deciding which claims should be emitted.

Whenever IdentityServer needs the claims for a user, it invokes the registered profile service with a context that presents detailed information about the current request, including

- the client that is making the request
- the identity of the user
- the type of the request (access token, id token, or userinfo)
- the requested claim types, which are the claims types associated with requested scopes and resources


Clients can request claims in several ways:

- Requesting an `IdentityResource` by including the scope parameter for the `IdentityResource` requests the claims associated with the `IdentityResource` in its `UserClaims` collection.
- Requesting an `ApiScope` by including the scope parameter for the `ApiScope` requests the claims associated with the `ApiScope` in its `UserClaims` collection.
- Requesting an `ApiResource` by including the resource indicator parameter for the `ApiResource` requests the claims associated with the `ApiResource` in its `UserClaims` collection.


The `RequestedClaimTypes` property of the `ProfileDataRequestContext` contains the collection of claims requested by the client.

### Emit Claims Based On The User Or Client Identity
Finally, you might have claims that are only appropriate for certain users or clients. Your `ProfileService` can add whatever filtering or logic that you like.

```c#
/// <summary>
/// This interface allows IdentityServer to connect to your user and profile store.
/// </summary>
public interface IProfileService
{
    /// <summary>
    /// This method is called whenever claims about the user are requested (e.g. during token creation or via the userinfo endpoint)
    /// </summary>
    /// <param name="context">The context.</param>
    /// <returns></returns>
    Task GetProfileDataAsync(ProfileDataRequestContext context);

    /// <summary>
    /// This method gets called whenever identity server needs to determine if the user is valid or active (e.g. if the user's account has been deactivated since they logged in).
    /// (e.g. during token issuance or validation).
    /// </summary>
    /// <param name="context">The context.</param>
    /// <returns></returns>
    Task IsActiveAsync(IsActiveContext context);
}
```
## The Key Management Lifecycle
- `Creation` : A new key is generated and saved to the storage (database or file system).
-` Announcement`: The key is published in the Discovery - Document (`.well-known/openid-configuration/jwks`) but is not used for signing yet. This allows clients to cache the new public key.
- `Active`: The key becomes the primary key used to sign all new tokens.
- `Retired` : The key is no longer used for signing but remains in the discovery document so that older, unexpired tokens can still be validated.
- Deleted	The key is permanently removed from storage.

## Default Configuration
By default, Duende IdentityServer enables automatic key management. If you don't specify a manual key, it will generate one for you.
```c#
builder.Services.AddIdentityServer()
    .AddSigningCredentials(); // Automatically manages RSA/ECDSA keys
 ```

 Key Timing Defaults
- `Rotation Interval`: 90 days (how long a key is used for signing).
- `Propagation Time`: 14 days (how long a new key is announced before it starts being used).
- `Retention Duration`: 14 days (how long a retired key stays around for validation).   

## Storage Options
Because keys must persist across server restarts, you need to tell Duende where to store them.

### Entity Framework (Recommended)
This stores keys in your SQL database, making it ideal for load-balanced environments.
```C#
builder.Services.AddIdentityServer()
    .AddSigningCredentials()
    .AddOperationalStore(options => {
        options.ConfigureDbContext = b => b.UseSqlServer(connectionString);
    });
```

### File System
Useful for simpler deployments or single-server setups.

```C#
builder.Services.AddIdentityServer(options => {
    options.KeyManagement.KeyPath = "/path/to/keys";
})
.AddSigningCredentials();
```
## Manual Key Management
If you prefer to manage your own certificates (e.g., from Azure Key Vault or a .pfx file), you can bypass the automatic system:

```C#
// Load from a file
builder.Services.AddIdentityServer()
    .AddSigningCredential(new X509Certificate2("cert.pfx", "password"));

// Load from a specific RSA key
builder.Services.AddIdentityServer()
    .AddSigningCredential(myRsaKey, SecurityAlgorithms.RsaSha256);
```

### Important: Data Protection
Duende uses `ASP.NET Core Data Protection`to encrypt the private keys before storing them in the database or file system. This ensures that even if someone gains access to your database, they cannot easily steal your private signing keys.


```c#
namespace Microsoft.AspNetCore.Authorization;

/// <summary>
/// Used for building policies.
/// </summary>
public class AuthorizationPolicyBuilder
{
    private static readonly DenyAnonymousAuthorizationRequirement _denyAnonymousAuthorizationRequirement = new();

    /// <summary>
    /// Creates a new instance of <see cref="AuthorizationPolicyBuilder"/>
    /// </summary>
    /// <param name="authenticationSchemes">An array of authentication schemes the policy should be evaluated against.</param>
    public AuthorizationPolicyBuilder(params string[] authenticationSchemes)
    {
        AddAuthenticationSchemes(authenticationSchemes);
    }

    /// <summary>
    /// Creates a new instance of <see cref="AuthorizationPolicyBuilder"/>.
    /// </summary>
    /// <param name="policy">The <see cref="AuthorizationPolicy"/> to copy.</param>
    public AuthorizationPolicyBuilder(AuthorizationPolicy policy)
    {
        Combine(policy);
    }

    /// <summary>
    /// Gets or sets a list of <see cref="IAuthorizationRequirement"/>s which must succeed for
    /// this policy to be successful.
    /// </summary>
    public IList<IAuthorizationRequirement> Requirements { get; set; } = new List<IAuthorizationRequirement>();

    /// <summary>
    /// Gets or sets a list authentication schemes the <see cref="AuthorizationPolicyBuilder.Requirements"/>
    /// are evaluated against.
    /// <para>
    /// When not specified, the requirements are evaluated against default schemes.
    /// </para>
    /// </summary>
    public IList<string> AuthenticationSchemes { get; set; } = new List<string>();

    /// <summary>
    /// Adds the specified authentication <paramref name="schemes"/> to the
    /// <see cref="AuthorizationPolicyBuilder.AuthenticationSchemes"/> for this instance.
    /// </summary>
    /// <param name="schemes">The schemes to add.</param>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public AuthorizationPolicyBuilder AddAuthenticationSchemes(params string[] schemes) => AddAuthenticationSchemesCore(schemes);

    private AuthorizationPolicyBuilder AddAuthenticationSchemesCore(IEnumerable<string> schemes)
    {
        foreach (var authType in schemes)
        {
            AuthenticationSchemes.Add(authType);
        }
        return this;
    }

    /// <summary>
    /// Adds the specified <paramref name="requirements"/> to the
    /// <see cref="AuthorizationPolicyBuilder.Requirements"/> for this instance.
    /// </summary>
    /// <param name="requirements">The authorization requirements to add.</param>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public AuthorizationPolicyBuilder AddRequirements(params IAuthorizationRequirement[] requirements) => AddRequirementsCore(requirements);

    private AuthorizationPolicyBuilder AddRequirementsCore(IEnumerable<IAuthorizationRequirement> requirements)
    {
        foreach (var req in requirements)
        {
            Requirements.Add(req);
        }
        return this;
    }

    /// <summary>
    /// Combines the specified <paramref name="policy"/> into the current instance.
    /// </summary>
    /// <param name="policy">The <see cref="AuthorizationPolicy"/> to combine.</param>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public AuthorizationPolicyBuilder Combine(AuthorizationPolicy policy)
    {
        ArgumentNullThrowHelper.ThrowIfNull(policy);

        AddAuthenticationSchemesCore(policy.AuthenticationSchemes);
        AddRequirementsCore(policy.Requirements);
        return this;
    }

    /// <summary>
    /// Adds a <see cref="ClaimsAuthorizationRequirement"/> to the current instance which requires
    /// that the current user has the specified claim and that the claim value must be one of the allowed values.
    /// </summary>
    /// <param name="claimType">The claim type required.</param>
    /// <param name="allowedValues">Optional list of claim values. If specified, the claim must match one or more of these values.</param>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public AuthorizationPolicyBuilder RequireClaim(string claimType, params string[] allowedValues)
    {
        ArgumentNullThrowHelper.ThrowIfNull(claimType);

        return RequireClaim(claimType, (IEnumerable<string>)allowedValues);
    }

    /// <summary>
    /// Adds a <see cref="ClaimsAuthorizationRequirement"/> to the current instance which requires
    /// that the current user has the specified claim and that the claim value must be one of the allowed values.
    /// </summary>
    /// <param name="claimType">The claim type required.</param>
    /// <param name="allowedValues">Optional list of claim values. If specified, the claim must match one or more of these values.</param>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public AuthorizationPolicyBuilder RequireClaim(string claimType, IEnumerable<string> allowedValues)
    {
        ArgumentNullThrowHelper.ThrowIfNull(claimType);

        Requirements.Add(new ClaimsAuthorizationRequirement(claimType, allowedValues));
        return this;
    }

    /// <summary>
    /// Adds a <see cref="ClaimsAuthorizationRequirement"/> to the current instance which requires
    /// that the current user has the specified claim.
    /// </summary>
    /// <param name="claimType">The claim type required, with no restrictions on claim value.</param>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public AuthorizationPolicyBuilder RequireClaim(string claimType)
    {
        ArgumentNullThrowHelper.ThrowIfNull(claimType);

        Requirements.Add(new ClaimsAuthorizationRequirement(claimType, allowedValues: null));
        return this;
    }

    /// <summary>
    /// Adds a <see cref="RolesAuthorizationRequirement"/> to the current instance which enforces that the current user
    /// must have at least one of the specified roles.
    /// </summary>
    /// <param name="roles">The allowed roles.</param>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public AuthorizationPolicyBuilder RequireRole(params string[] roles)
    {
        ArgumentNullThrowHelper.ThrowIfNull(roles);

        return RequireRole((IEnumerable<string>)roles);
    }

    /// <summary>
    /// Adds a <see cref="RolesAuthorizationRequirement"/> to the current instance which enforces that the current user
    /// must have at least one of the specified roles.
    /// </summary>
    /// <param name="roles">The allowed roles.</param>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public AuthorizationPolicyBuilder RequireRole(IEnumerable<string> roles)
    {
        ArgumentNullThrowHelper.ThrowIfNull(roles);

        Requirements.Add(new RolesAuthorizationRequirement(roles));
        return this;
    }

    /// <summary>
    /// Adds a <see cref="NameAuthorizationRequirement"/> to the current instance which enforces that the current user matches the specified name.
    /// </summary>
    /// <param name="userName">The user name the current user must have.</param>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public AuthorizationPolicyBuilder RequireUserName(string userName)
    {
        ArgumentNullThrowHelper.ThrowIfNull(userName);

        Requirements.Add(new NameAuthorizationRequirement(userName));
        return this;
    }

    /// <summary>
    /// Adds <see cref="DenyAnonymousAuthorizationRequirement"/> to the current instance which enforces that the current user is authenticated.
    /// </summary>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public AuthorizationPolicyBuilder RequireAuthenticatedUser()
    {
        Requirements.Add(_denyAnonymousAuthorizationRequirement);
        return this;
    }

    /// <summary>
    /// Adds an <see cref="AssertionRequirement"/> to the current instance.
    /// </summary>
    /// <param name="handler">The handler to evaluate during authorization.</param>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public AuthorizationPolicyBuilder RequireAssertion(Func<AuthorizationHandlerContext, bool> handler)
    {
        ArgumentNullThrowHelper.ThrowIfNull(handler);

        Requirements.Add(new AssertionRequirement(handler));
        return this;
    }

    /// <summary>
    /// Adds an <see cref="AssertionRequirement"/> to the current instance.
    /// </summary>
    /// <param name="handler">The handler to evaluate during authorization.</param>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public AuthorizationPolicyBuilder RequireAssertion(Func<AuthorizationHandlerContext, Task<bool>> handler)
    {
        ArgumentNullThrowHelper.ThrowIfNull(handler);

        Requirements.Add(new AssertionRequirement(handler));
        return this;
    }

    /// <summary>
    /// Builds a new <see cref="AuthorizationPolicy"/> from the requirements
    /// in this instance.
    /// </summary>
    /// <returns>
    /// A new <see cref="AuthorizationPolicy"/> built from the requirements in this instance.
    /// </returns>
    public AuthorizationPolicy Build()
    {
        return new AuthorizationPolicy(Requirements, AuthenticationSchemes.Distinct());
    }
}
```

When you write `policy.RequireRole("Admin")`, .NET is actually creating a `RolesAuthorizationRequirement `for you under the hood and adding it to that policy.

```c#
public class MinimumExperienceRequirement : IAuthorizationRequirement
{
    public int Years { get; }
    public MinimumExperienceRequirement(int years) => Years = years;
}

A policy is a named group of rules
options.AddPolicy("SeniorDevOnly", policy => 
{
    policy.RequireAuthenticatedUser(); // Requirement 1
    policy.AddRequirements(new MinimumExperienceRequirement(5)); // Requirement 2
});
```

Using multiple handlers for a single requirement is a powerful pattern. It allows you to follow the "OR" logic principle: a requirement is satisfied if any associated handler succeeds.
The Scenario: "Proof of Identity"

Imagine a policy that requires a user to be "Verified." A user can be verified in two ways:
- By having a Government ID claim.
- By having a Trusted Employee role.

Instead of writing one giant, messy if/else block, you create one Requirement and two Handlers.

```c#
//This is just the marker that says "The user must be verified."
public class IsVerifiedRequirement : IAuthorizationRequirement { }

//We create two separate classes. .NET will automatically find and run both of them.

public class GovernmentIdHandler : AuthorizationHandler<IsVerifiedRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, IsVerifiedRequirement requirement)
    {
        if (context.User.HasClaim(c => c.Type == "GovID"))
        {
            context.Succeed(requirement); // Requirement satisfied!
        }
        return Task.CompletedTask;
    }
}

public class EmployeeRoleHandler : AuthorizationHandler<IsVerifiedRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, IsVerifiedRequirement requirement)
    {
        if (context.User.IsInRole("TrustedEmployee"))
        {
            context.Succeed(requirement); // Requirement satisfied!
        }
        return Task.CompletedTask;
    }
}

// You must register both handlers and the policy.

// Register Handlers
builder.Services.AddSingleton<IAuthorizationHandler, GovernmentIdHandler>();
builder.Services.AddSingleton<IAuthorizationHandler, EmployeeRoleHandler>();

// Register Policy
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("VerificationPolicy", policy =>
        policy.AddRequirements(new IsVerifiedRequirement()));
});

```
One Policy + Multiple Requirements = AND logic (User must pass all).

One Requirement + Multiple Handlers = OR logic (User must pass any).


```c#
//simple inline
// Program.cs
builder.Services.AddAuthorization(options => {
    options.AddPolicy("CanWithdrawFunds", policy => 
        policy.RequireAssertion(context => 
            context.User.HasClaim(c => c.Type == "AccountStatus" && c.Value == "Active") &&
            context.User.HasClaim(c => c.Type == "DailyLimit") // Logic is trapped here
        ));
});


```

```c#
public class MinimumBalanceRequirement : IAuthorizationRequirement {
    public int Amount { get; }
    public MinimumBalanceRequirement(int amount) => Amount = amount;
}

public class MinimumBalanceHandler : AuthorizationHandler<MinimumBalanceRequirement> {
    protected override Task HandleRequirementAsync(...) {
        // Here you could call a Database or API to check the real-time balance
        if (UserBalance >= requirement.Amount) context.Succeed(requirement);
        return Task.CompletedTask;
    }
}
//The Policy in Program.cs:
options.AddPolicy("HighValueWithdrawal", policy => 
    policy.AddRequirements(new MinimumBalanceRequirement(10000)));
```

```c#
  public AuthorizationPolicyBuilder RequireClaim(string claimType, IEnumerable<string> allowedValues)
    {
        ArgumentNullThrowHelper.ThrowIfNull(claimType);

        Requirements.Add(new ClaimsAuthorizationRequirement(claimType, allowedValues));
        return this;
    }

     public AuthorizationPolicyBuilder RequireRole(IEnumerable<string> roles)
    {
        ArgumentNullThrowHelper.ThrowIfNull(roles);

        Requirements.Add(new RolesAuthorizationRequirement(roles));
        return this;
    }

      public AuthorizationPolicyBuilder RequireUserName(string userName)
    {
        ArgumentNullThrowHelper.ThrowIfNull(userName);

        Requirements.Add(new NameAuthorizationRequirement(userName));
        return this;
    }

        /// <summary>
    /// Adds <see cref="DenyAnonymousAuthorizationRequirement"/> to the current instance which enforces that the current user is authenticated.
    /// </summary>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public AuthorizationPolicyBuilder RequireAuthenticatedUser()
    {
        Requirements.Add(_denyAnonymousAuthorizationRequirement);
        return this;
    }

        /// <summary>
    /// Adds an <see cref="AssertionRequirement"/> to the current instance.
    /// </summary>
    /// <param name="handler">The handler to evaluate during authorization.</param>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public AuthorizationPolicyBuilder RequireAssertion(Func<AuthorizationHandlerContext, bool> handler)
    {
        ArgumentNullThrowHelper.ThrowIfNull(handler);

        Requirements.Add(new AssertionRequirement(handler));
        return this;
    }

  ```

  ```c#
  /// <summary>
/// Implements an <see cref="IAuthorizationHandler"/> and <see cref="IAuthorizationRequirement"/>
/// which requires at least one role claim whose value must be any of the allowed roles.
/// </summary>
public class RolesAuthorizationRequirement : AuthorizationHandler<RolesAuthorizationRequirement>, IAuthorizationRequirement
{
    /// <summary>
    /// Creates a new instance of <see cref="RolesAuthorizationRequirement"/>.
    /// </summary>
    /// <param name="allowedRoles">A collection of allowed roles.</param>
    public RolesAuthorizationRequirement(IEnumerable<string> allowedRoles)
    {
        ArgumentNullThrowHelper.ThrowIfNull(allowedRoles);

        if (!allowedRoles.Any())
        {
            throw new InvalidOperationException(Resources.Exception_RoleRequirementEmpty);
        }
        AllowedRoles = allowedRoles;
    }

    /// <summary>
    /// Gets the collection of allowed roles.
    /// </summary>
    public IEnumerable<string> AllowedRoles { get; }

    /// <summary>
    /// Makes a decision if authorization is allowed based on a specific requirement.
    /// </summary>
    /// <param name="context">The authorization context.</param>
    /// <param name="requirement">The requirement to evaluate.</param>
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, RolesAuthorizationRequirement requirement)
    {
        if (context.User != null)
        {
            var found = false;

            foreach (var role in requirement.AllowedRoles)
            {
                if (context.User.IsInRole(role))
                {
                    found = true;
                    break;
                }
            }

            if (found)
            {
                context.Succeed(requirement);
            }
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public override string ToString()
    {
        var roles = $"User.IsInRole must be true for one of the following roles: ({string.Join("|", AllowedRoles)})";

        return $"{nameof(RolesAuthorizationRequirement)}:{roles}";
    }
}

```


```c#
///DefaultClaimsService.cs


namespace Duende.IdentityServer.Services;

/// <summary>
/// Default claims provider implementation
/// </summary>
public class DefaultClaimsService : IClaimsService
{
    /// <summary>
    /// The logger
    /// </summary>
    protected readonly ILogger Logger;

    /// <summary>
    /// The user service
    /// </summary>
    protected readonly IProfileService Profile;

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultClaimsService"/> class.
    /// </summary>
    /// <param name="profile">The profile service</param>
    /// <param name="logger">The logger</param>
    public DefaultClaimsService(IProfileService profile, ILogger<DefaultClaimsService> logger)
    {
        Logger = logger;
        Profile = profile;
    }

    /// <summary>
    /// Returns claims for an identity token
    /// </summary>
    /// <param name="subject">The subject</param>
    /// <param name="resources">The requested resources</param>
    /// <param name="includeAllIdentityClaims">Specifies if all claims should be included in the token, or if the userinfo endpoint can be used to retrieve them</param>
    /// <param name="request">The raw request</param>
    /// <returns>
    /// Claims for the identity token
    /// </returns>
    public virtual async Task<IEnumerable<Claim>> GetIdentityTokenClaimsAsync(ClaimsPrincipal subject, ResourceValidationResult resources, bool includeAllIdentityClaims, ValidatedRequest request)
    {
        using var activity = Tracing.ServiceActivitySource.StartActivity("DefaultClaimsService.GetIdentityTokenClaims");

        Logger.LogDebug("Getting claims for identity token for subject: {subject} and client: {clientId}",
            subject.GetSubjectId(),
            request.Client.ClientId);

        var outputClaims = new List<Claim>(GetStandardSubjectClaims(subject));
        outputClaims.AddRange(GetOptionalClaims(subject));

        // fetch all identity claims that need to go into the id token
        if (includeAllIdentityClaims || request.Client.AlwaysIncludeUserClaimsInIdToken)
        {
            var additionalClaimTypes = new List<string>();

            foreach (var identityResource in resources.Resources.IdentityResources)
            {
                foreach (var userClaim in identityResource.UserClaims)
                {
                    additionalClaimTypes.Add(userClaim);
                }
            }

            // filter so we don't ask for claim types that we will eventually filter out
            additionalClaimTypes = FilterRequestedClaimTypes(additionalClaimTypes).ToList();

            var context = new ProfileDataRequestContext(
                subject,
                request.Client,
                IdentityServerConstants.ProfileDataCallers.ClaimsProviderIdentityToken,
                additionalClaimTypes)
            {
                RequestedResources = resources,
                ValidatedRequest = request
            };

            await Profile.GetProfileDataAsync(context);

            var claims = FilterProtocolClaims(context.IssuedClaims);
            if (claims != null)
            {
                outputClaims.AddRange(claims);
            }
        }
        else
        {
            Logger.LogDebug("In addition to an id_token, an access_token was requested. No claims other than sub are included in the id_token. To obtain more user claims, either use the user info endpoint or set AlwaysIncludeUserClaimsInIdToken on the client configuration.");
        }

        return outputClaims;
    }

    /// <summary>
    /// Returns claims for an access token.
    /// </summary>
    /// <param name="subject">The subject.</param>
    /// <param name="resourceResult">The validated resource result</param>
    /// <param name="request">The raw request.</param>
    /// <returns>
    /// Claims for the access token
    /// </returns>
    public virtual async Task<IEnumerable<Claim>> GetAccessTokenClaimsAsync(ClaimsPrincipal subject, ResourceValidationResult resourceResult, ValidatedRequest request)
    {
        using var activity = Tracing.ServiceActivitySource.StartActivity("DefaultClaimsService.GetAccessTokenClaims");

        Logger.LogDebug("Getting claims for access token for client: {clientId}", request.Client.ClientId);

        var outputClaims = new List<Claim>
        {
            new Claim(JwtClaimTypes.ClientId, request.ClientId)
        };

        // log if client ID is overwritten
        if (!string.Equals(request.ClientId, request.Client.ClientId, StringComparison.Ordinal))
        {
            Logger.LogDebug("Client {clientId} is impersonating {impersonatedClientId}", request.Client.ClientId, request.ClientId);
        }

        // check for client claims
        if (request.ClientClaims != null && request.ClientClaims.Count > 0)
        {
            if (subject == null || request.Client.AlwaysSendClientClaims)
            {
                foreach (var claim in request.ClientClaims)
                {
                    var claimType = claim.Type;

                    if (request.Client.ClientClaimsPrefix.IsPresent())
                    {
                        claimType = request.Client.ClientClaimsPrefix + claimType;
                    }

                    outputClaims.Add(new Claim(claimType, claim.Value, claim.ValueType));
                }
            }
        }

        // add scopes (filter offline_access)
        // we use the ScopeValues collection rather than the Resources.Scopes because we support dynamic scope values
        // from the request, so this issues those in the token.
        foreach (var scope in resourceResult.RawScopeValues.Where(x => x != IdentityServerConstants.StandardScopes.OfflineAccess))
        {
            outputClaims.Add(new Claim(JwtClaimTypes.Scope, scope));
        }

        // a user is involved
        if (subject != null)
        {
            if (resourceResult.Resources.OfflineAccess)
            {
                outputClaims.Add(new Claim(JwtClaimTypes.Scope, IdentityServerConstants.StandardScopes.OfflineAccess));
            }

            Logger.LogDebug("Getting claims for access token for subject: {subject}", subject.GetSubjectId());

            outputClaims.AddRange(GetStandardSubjectClaims(subject));
            outputClaims.AddRange(GetOptionalClaims(subject));

            // fetch all resource claims that need to go into the access token
            var additionalClaimTypes = new List<string>();
            foreach (var api in resourceResult.Resources.ApiResources)
            {
                // add claims configured on api resource
                if (api.UserClaims != null)
                {
                    foreach (var claim in api.UserClaims)
                    {
                        additionalClaimTypes.Add(claim);
                    }
                }
            }

            foreach (var scope in resourceResult.Resources.ApiScopes)
            {
                // add claims configured on scopes
                if (scope.UserClaims != null)
                {
                    foreach (var claim in scope.UserClaims)
                    {
                        additionalClaimTypes.Add(claim);
                    }
                }
            }

            // filter so we don't ask for claim types that we will eventually filter out
            additionalClaimTypes = FilterRequestedClaimTypes(additionalClaimTypes).ToList();

            var context = new ProfileDataRequestContext(
                subject,
                request.Client,
                IdentityServerConstants.ProfileDataCallers.ClaimsProviderAccessToken,
                additionalClaimTypes.Distinct())
            {
                RequestedResources = resourceResult,
                ValidatedRequest = request
            };

            await Profile.GetProfileDataAsync(context);

            var claims = FilterProtocolClaims(context.IssuedClaims);
            if (claims != null)
            {
                outputClaims.AddRange(claims);
            }
        }

        return outputClaims;
    }

    /// <summary>
    /// Gets the standard subject claims.
    /// </summary>
    /// <param name="subject">The subject.</param>
    /// <returns>A list of standard claims</returns>
    protected virtual IEnumerable<Claim> GetStandardSubjectClaims(ClaimsPrincipal subject)
    {
        var claims = new List<Claim>
        {
            new Claim(JwtClaimTypes.Subject, subject.GetSubjectId()),
            new Claim(JwtClaimTypes.AuthenticationTime, subject.GetAuthenticationTimeEpoch().ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),
            new Claim(JwtClaimTypes.IdentityProvider, subject.GetIdentityProvider())
        };

        claims.AddRange(subject.GetAuthenticationMethods());

        return claims;
    }

    /// <summary>
    /// Gets additional (and optional) claims from the cookie or incoming subject.
    /// </summary>
    /// <param name="subject">The subject.</param>
    /// <returns>Additional claims</returns>
    protected virtual IEnumerable<Claim> GetOptionalClaims(ClaimsPrincipal subject)
    {
        var claims = new List<Claim>();

        var acr = subject.FindFirst(JwtClaimTypes.AuthenticationContextClassReference);
        if (acr != null)
        {
            claims.Add(acr);
        }

        return claims;
    }

    /// <summary>
    /// Filters out protocol claims like amr, nonce etc..
    /// </summary>
    /// <param name="claims">The claims.</param>
    /// <returns></returns>
    protected virtual IEnumerable<Claim> FilterProtocolClaims(IEnumerable<Claim> claims)
    {
        var claimsToFilter = claims.Where(x => Constants.Filters.ClaimsServiceFilterClaimTypes.Contains(x.Type));
        if (claimsToFilter.Any())
        {
            var types = claimsToFilter.Select(x => x.Type);
            Logger.LogDebug("Claim types from profile service that were filtered: {claimTypes}", types);
        }
        return claims.Except(claimsToFilter);
    }

    /// <summary>
    /// Filters out protocol claims like amr, nonce etc..
    /// </summary>
    /// <param name="claimTypes">The claim types.</param>
    protected virtual IEnumerable<string> FilterRequestedClaimTypes(IEnumerable<string> claimTypes)
    {
        var claimTypesToFilter = claimTypes.Where(x => Constants.Filters.ClaimsServiceFilterClaimTypes.Contains(x));
        return claimTypes.Except(claimTypesToFilter);
    }
}
```

Key Responsibilities

The service performs three main tasks:

- Collection: It identifies which claims are needed based on the requested Scopes and Resources.
- Sourcing: It calls the IProfileService to fetch actual values for those claims from your user store.
- Sanitization: It filters out "protocol claims" (internal OIDC technical markers) that shouldn't be leaked into tokens.


`GetIdentityTokenClaimsAsync`: Always Included: Subject ID (`sub`), Authentication Time (`auth_time`), Identity Provider (`idp`), and Authentication Methods (`amr`)

```c#

    public static readonly Dictionary<string, IEnumerable<string>> ScopeToClaimsMapping = new Dictionary<string, IEnumerable<string>>
    {
        { IdentityServerConstants.StandardScopes.Profile, new[]
        {
            JwtClaimTypes.Name,
            JwtClaimTypes.FamilyName,
            JwtClaimTypes.GivenName,
            JwtClaimTypes.MiddleName,
            JwtClaimTypes.NickName,
            JwtClaimTypes.PreferredUserName,
            JwtClaimTypes.Profile,
            JwtClaimTypes.Picture,
            JwtClaimTypes.WebSite,
            JwtClaimTypes.Gender,
            JwtClaimTypes.BirthDate,
            JwtClaimTypes.ZoneInfo,
            JwtClaimTypes.Locale,
            JwtClaimTypes.UpdatedAt
        }},
        { IdentityServerConstants.StandardScopes.Email, new[]
        {
            JwtClaimTypes.Email,
            JwtClaimTypes.EmailVerified
        }},
        { IdentityServerConstants.StandardScopes.Address, new[]
        {
            JwtClaimTypes.Address
        }},
        { IdentityServerConstants.StandardScopes.Phone, new[]
        {
            JwtClaimTypes.PhoneNumber,
            JwtClaimTypes.PhoneNumberVerified
        }},
        { IdentityServerConstants.StandardScopes.OpenId, new[]
        {
            JwtClaimTypes.Subject
        }}
    };


    public class Filters
    {
        // filter for claims from an incoming access token (e.g. used at the user profile endpoint)
        public static readonly string[] ProtocolClaimsFilter = {
            JwtClaimTypes.AccessTokenHash,
            JwtClaimTypes.Audience,
            JwtClaimTypes.AuthorizedParty,
            JwtClaimTypes.AuthorizationCodeHash,
            JwtClaimTypes.ClientId,
            JwtClaimTypes.Expiration,
            JwtClaimTypes.IssuedAt,
            JwtClaimTypes.Issuer,
            JwtClaimTypes.JwtId,
            JwtClaimTypes.Nonce,
            JwtClaimTypes.NotBefore,
            JwtClaimTypes.ReferenceTokenId,
            JwtClaimTypes.SessionId,
            JwtClaimTypes.Scope
        };

        // filter list for claims returned from profile service prior to creating tokens
        public static readonly string[] ClaimsServiceFilterClaimTypes = {
            // TODO: consider JwtClaimTypes.AuthenticationContextClassReference,
            JwtClaimTypes.AccessTokenHash,
            JwtClaimTypes.Audience,
            JwtClaimTypes.AuthenticationMethod,
            JwtClaimTypes.AuthenticationTime,
            JwtClaimTypes.AuthorizedParty,
            JwtClaimTypes.AuthorizationCodeHash,
            JwtClaimTypes.ClientId,
            JwtClaimTypes.Expiration,
            JwtClaimTypes.IdentityProvider,
            JwtClaimTypes.IssuedAt,
            JwtClaimTypes.Issuer,
            JwtClaimTypes.JwtId,
            JwtClaimTypes.Nonce,
            JwtClaimTypes.NotBefore,
            JwtClaimTypes.ReferenceTokenId,
            JwtClaimTypes.SessionId,
            JwtClaimTypes.Subject,
            JwtClaimTypes.Scope,
            JwtClaimTypes.Confirmation
        };

        public static readonly string[] JwtRequestClaimTypesFilter = {
            JwtClaimTypes.Audience,
            JwtClaimTypes.Expiration,
            JwtClaimTypes.IssuedAt,
            JwtClaimTypes.Issuer,
            JwtClaimTypes.NotBefore,
            JwtClaimTypes.JwtId
        };
    }


 ```   

Now that the Claims Service has a "shopping list" of claim types, it prepares a `ProfileDataRequestContext`.

- `ClaimsServiceFilterClaimTypes` (Outgoing)
- `ProtocolClaimsFilter` (Incoming)

It creates the ProfileDataRequestContext. Note the caller: `ClaimsProviderAccessToken` or `ClaimsProviderIdentityToken`

Access tokens can be either application access tokens or delegated access tokens. The tokens have different claims and are managed and stored differently. An application access token is typically stored once in the app until it expires, while a delegated access token is stored per user, either in a cookie or in a secure server cache.

The core FAPI functionality is split into two documents, with a third that describes the attacker model
- FAPI 2.0 Security Profile (Final)
- FAPI 2.0 Attacker Model (Final)
- FAPI 2.0 Message Signing (Draft)
Specifications Referenced by FAPI
- RFC 6749 - OAuth 2.0 Framework
- RFC 6750 - OAuth 2.0 Bearer Token Usage
- RFC 7521 - Assertion Framework for OAuth 2.0 Client- Authentication and Authorization Grants
- RFC 7523 - JWT Profile for OAuth 2.0 Client- Authentication and Authorization Grants
- RFC 7636 - Proof Key for Code Exchange
- RFC 7662 - OAuth 2.0 Token Introspection
- RFC 8252 - OAuth 2.0 for Native Apps BCP
- RFC 8414 - OAuth 2.0 Authorization Server Metadata
- RFC 8705 - Mutual TLS Client Authentication and- Certificate-Bound Access Tokens
- RFC 8725 - JSON Web Token Best Practices
- RFC 9101 - JWT Secured Authorization Request (JAR)
- RFC 9126 - Pushed Authorization Requests (PAR)
- RFC 9207 - OAuth 2.0 Authorization Server Issuer- Identification
- RFC 9449 - DPoP: Demonstrating Proof-of-Possession at- the Application Layer
- RFC 9421 - HTTP Message Signatures
- RFC 9530 - HTTP Digest Headers
- RFC 9700 - Best Current Practice for OAuth 2.0 Security
- RFC 9701 - JWT Response for OAuth Token Introspection
- JWT Secured Authorization Response Mode for OAuth 2.0(JARM)


there are three key benefits of using FAPI specifications for strengthening API security outlined by the FAPI working group:

- Clear, point-by-point specifications that implementers can use as a “checklist.”
- Exhaustive conformance tests to allow implementers to better secure their software and ensure interoperability.
- A standards-based approach to providing security for complex interactions (e.g., decoupled authZ flows via CIBA, grant management, pushed request objects).

FAPI 2.0 has a broader scope than FAPI 1.0 and aims for improved interoperability between the client and authorization server and between the client and resource server (APIs). This is especially important in ecosystems such as open banking, which grow via the network effect.

- FAPI 2.0 provides the option of using rich authorization requests to obtain a more fine-grained and richer context for authorizing transactions and API access. This ensures customers understand what they are authorizing, which can help with personalization, improving trust and retention.
- FAPI 2.0 provides a more versatile and approachable option for sender-constraining tokens and protecting against replay attacks using DPoP. This can help with the adoption of a robust security mechanism for protecting access and refresh tokens.
- FAPI 2.0 defines protection levels where the baseline security profile aims to be secure against threats described in the security threat model. An additional (advanced) profile adds non-repudiation through message signing

the Colombian finance regulator - has issued a press release on its strategy of digitalizing the financial system to increase participation and foster competition and innovation. The SFC has been forward-looking and mandated that Colombian banks implement FAPI 2.0 in its External Circular 004 2024 (7th Feb 2024) on Open Finance and Commercialization of Technology and Digital Infrastructure.