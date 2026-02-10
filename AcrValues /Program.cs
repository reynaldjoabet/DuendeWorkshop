

using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Duende.IdentityServer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authentication.Google;
using Rsk.AspNetCore.Authentication.Saml2p;
using Rsk.Saml.DuendeIdentityServer.DynamicProviders;
using Rsk.TokenExchange.DuendeIdentityServer;

public partial class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddIdentityServer(options =>
        {
            options.Events.RaiseErrorEvents = true;
            options.Events.RaiseInformationEvents = true;
            options.Events.RaiseFailureEvents = true;
            options.Events.RaiseSuccessEvents = true;

            // see https://docs.duendesoftware.com/identityserver/fundamentals/resources
            options.EmitStaticAudienceClaim = true;
        })
        .AddInMemoryIdentityProviders(new List<Duende.IdentityServer.Models.IdentityProvider>
        {
            // Predefined identity providers can be added here
        })
        .AddTokenExchange()
        // SP configuration - dynamic providers
        .AddSamlDynamicProvider(options =>
        {
            // unstorable/reusable data, such as license information and events. This will override the data stored
            options.Licensee = "your-licensee";
            options.LicenseKey = "your-license-key";
        })
        //Use EntityFramework store for storing identity providers
        //.AddIdentityProviderStore<SamlIdentityProviderStore>();

        //use in memory store for storing identity providers
        .AddInMemoryIdentityProviders(new List<SamlDynamicIdentityProvider>
            {
                    new SamlDynamicIdentityProvider
                    {
                        SamlAuthenticationOptions = new Saml2pAuthenticationOptions
                        {
                            // The IdP you want to integrate with
                            IdentityProviderOptions = new IdpOptions
                            {
                                EntityId = "https://localhost:5000",
                                SigningCertificates = { X509CertificateLoader.LoadCertificateFromFile("idsrv3test.cer") },
                                SingleSignOnEndpoint = new SamlEndpoint("https://localhost:5000/saml/sso", SamlBindingTypes.HttpRedirect),
                                SingleLogoutEndpoint = new SamlEndpoint("https://localhost:5000/saml/slo", SamlBindingTypes.HttpRedirect)
                            },

                            // Details about yourself (the SP)
                            ServiceProviderOptions = new SpOptions
                            {
                                EntityId = "https://localhost:5004/saml",
                                MetadataPath = "/federation/saml/metadata",
                                SignAuthenticationRequests = false // OPTIONAL - use if you want to sign your auth requests
                            },

                            NameIdClaimType = "sub",
                            CallbackPath = "/federation/saml/signin-saml", // Duende prefixes "/federation/{scheme}" to all paths
                            SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme,
                        },

                        Scheme = "saml",
                        DisplayName = "saml",
                        Enabled = true,
                    }
            })
            .AddOidcDynamicProvider()
        .AddIdentityProviderStore<MyCustomIdentityProviderStore>() // Your custom store
        .AddIdentityProviderStoreCache<MyCustomIdentityProviderStore>();
        builder.Services.AddDynamicProviders(); // Required for dynamic IdP registration


        builder.Services.AddAuthentication()
           .AddOpenIdConnect("oidc", "Sign-in with demo.duendesoftware.com", options =>
            {
                options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                options.SignOutScheme = IdentityServerConstants.SignoutScheme;
                options.SaveTokens = true;

                options.Authority = "https://demo.duendesoftware.com";
                options.ClientId = "interactive.confidential";
                options.ClientSecret = "secret";
                options.ResponseType = "code";

                options.TokenValidationParameters = new()
                {
                    NameClaimType = "name",
                    RoleClaimType = "role"
                };
            })
            .AddCookie(o => o.LoginPath = new PathString("/login"))
            // You must first create an app with Facebook and add its ID and Secret to your user-secrets.
            // https://developers.facebook.com/apps/
            // https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow#login
            // .AddFacebook(o =>
            // {
            //     o.AppId = builder.Configuration["facebook:appid"] ?? string.Empty;
            //     o.AppSecret = builder.Configuration["facebook:appsecret"] ?? string.Empty;
            //     o.Scope.Add("email");
            //     o.Fields.Add("name");
            //     o.Fields.Add("email");
            //     o.SaveTokens = true;
            //     o.Events = new OAuthEvents()
            //     {
            //         OnRemoteFailure = HandleOnRemoteFailure
            //     };
            // })
            // You must first create an app with Google and add its ID and Secret to your user-secrets.
            // https://console.developers.google.com/project
            // https://developers.google.com/identity/protocols/OAuth2WebServer
            // https://developers.google.com/+/web/people/
            .AddGoogle(o =>
            {
                o.ClientId = builder.Configuration["google:clientid"] ?? string.Empty;
                o.ClientSecret = builder.Configuration["google:clientsecret"] ?? string.Empty;
                o.AuthorizationEndpoint += "?prompt=consent"; // Hack so we always get a refresh token, it only comes on the first authorization response
                o.AccessType = "offline";
                o.SaveTokens = true;
                o.Events = new OAuthEvents()
                {
                    //OnRemoteFailure = HandleOnRemoteFailure
                };
                o.ClaimActions.MapJsonSubKey("urn:google:image", "image", "url");
                o.ClaimActions.Remove(ClaimTypes.GivenName);
            })

            /* Azure AD app model v2 has restrictions that prevent the use of plain HTTP for redirect URLs.
               Therefore, to authenticate through microsoft accounts, try out the sample using the following URL:
               https://localhost:44318/
            */
            // You must first create an app with Microsoft Account and add its ID and Secret to your user-secrets.
            // https://azure.microsoft.com/en-us/documentation/articles/active-directory-v2-app-registration/
            // https://apps.dev.microsoft.com/
            .AddMicrosoftAccount(o =>
            {
                o.ClientId = builder.Configuration["microsoftaccount:clientid"] ?? string.Empty;
                o.ClientSecret = builder.Configuration["microsoftaccount:clientsecret"] ?? string.Empty;
                o.SaveTokens = true;
                o.Scope.Add("offline_access");
                o.Events = new OAuthEvents()
                {
                    //OnRemoteFailure = HandleOnRemoteFailure
                };
            })
            // You must first create an app with GitHub and add its ID and Secret to your user-secrets.
            // https://github.com/settings/applications/
            // https://docs.github.com/en/developers/apps/authorizing-oauth-apps
            .AddOAuth("GitHub", "Github", o =>
            {
                o.ClientId = builder.Configuration["github:clientid"] ?? string.Empty;
                o.ClientSecret = builder.Configuration["github:clientsecret"] ?? string.Empty;
                o.CallbackPath = new PathString("/signin-github");
                o.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
                o.TokenEndpoint = "https://github.com/login/oauth/access_token";
                o.UserInformationEndpoint = "https://api.github.com/user";
                o.ClaimsIssuer = "OAuth2-Github";
                o.SaveTokens = true;
                // Retrieving user information is unique to each provider.
                o.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
                o.ClaimActions.MapJsonKey(ClaimTypes.Name, "login");
                o.ClaimActions.MapJsonKey("urn:github:name", "name");
                o.ClaimActions.MapJsonKey(ClaimTypes.Email, "email", ClaimValueTypes.Email);
                o.ClaimActions.MapJsonKey("urn:github:url", "url");
                o.Events = new OAuthEvents
                {
                    //OnRemoteFailure = HandleOnRemoteFailure,
                    OnCreatingTicket = async context =>
                    {
                        // Get the GitHub user
                        var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
                        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
                        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                        var response = await context.Backchannel.SendAsync(request, context.HttpContext.RequestAborted);
                        response.EnsureSuccessStatusCode();

                        using (var user = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
                        {
                            context.RunClaimActions(user.RootElement);
                        }
                    }
                };
            })
            // You must first create an app with GitHub and add its ID and Secret to your user-secrets.
            // https://github.com/settings/applications/
            // https://docs.github.com/en/developers/apps/authorizing-oauth-apps
            .AddOAuth("GitHub-AccessToken", "GitHub AccessToken only", o =>
            {
                o.ClientId = builder.Configuration["github-token:clientid"] ?? string.Empty;
                o.ClientSecret = builder.Configuration["github-token:clientsecret"] ?? string.Empty;
                o.CallbackPath = new PathString("/signin-github-token");
                o.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
                o.TokenEndpoint = "https://github.com/login/oauth/access_token";
                o.SaveTokens = true;
                o.Events = new OAuthEvents()
                {
                    //OnRemoteFailure = HandleOnRemoteFailure
                };
            })
            // https://demo.identityserver.io/
            // https://github.com/IdentityServer/IdentityServer4.Demo/blob/master/src/IdentityServer4Demo/Config.cs
            .AddOAuth("IdentityServer", "Identity Server", o =>
            {
                o.ClientId = "interactive.public";
                o.ClientSecret = "secret";
                o.CallbackPath = new PathString("/signin-identityserver");
                o.AuthorizationEndpoint = "https://demo.identityserver.io/connect/authorize";
                o.TokenEndpoint = "https://demo.identityserver.io/connect/token";
                o.UserInformationEndpoint = "https://demo.identityserver.io/connect/userinfo";
                o.ClaimsIssuer = "IdentityServer";
                o.SaveTokens = true;
                o.UsePkce = true;
                // Retrieving user information is unique to each provider.
                o.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "sub");
                o.ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
                o.ClaimActions.MapJsonKey(ClaimTypes.Email, "email", ClaimValueTypes.Email);
                o.ClaimActions.MapJsonKey(ClaimTypes.GivenName, "given_name");
                o.ClaimActions.MapJsonKey(ClaimTypes.Surname, "family_name");
                o.ClaimActions.MapJsonKey("email_verified", "email_verified");
                o.ClaimActions.MapJsonKey(ClaimTypes.Uri, "website");
                o.Scope.Add("openid");
                o.Scope.Add("profile");
                o.Scope.Add("email");
                o.Scope.Add("offline_access");
                o.Events = new OAuthEvents
                {
                    //OnRemoteFailure = HandleOnRemoteFailure,
                    OnCreatingTicket = async context =>
                    {
                        // Get the user
                        var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
                        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
                        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                        var response = await context.Backchannel.SendAsync(request, context.HttpContext.RequestAborted);
                        response.EnsureSuccessStatusCode();

                        using (var user = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
                        {
                            context.RunClaimActions(user.RootElement);
                        }
                    }
                };
            });
        var app = builder.Build();
        app.Run();



        builder.Services.AddTransient<DynamicOptions>();
        // the library will discover ConfigureAuthenticationOptions implementations when creating dynamic schemes






    }
}