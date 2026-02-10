using Duende.IdentityServer;
using Duende.IdentityServer.Services;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.SqlServer;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Serilog;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Duende.IdentityServer.Configuration;
using System.Threading.Tasks;
using Microsoft.AspNetCore.SignalR;
namespace DuendeProfileServiceAspNetCoreIdentity;

internal static class HostingExtensions
{
    public static async Task<WebApplication> ConfigureServices(this WebApplicationBuilder builder)
    {
        builder.Services.AddRazorPages();

        // builder.Services.AddDbContext<ApplicationDbContext>(options =>
        //     options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

        // builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
        //     .AddEntityFrameworkStores<ApplicationDbContext>()
        //     .AddDefaultTokenProviders();

        builder.Services.AddAuthentication("Default")
            .AddPolicyScheme("Default", "Default scheme", options =>
            {
                options.ForwardDefaultSelector = context =>
                {
                    // If this is an API request, use JWT
                    if (context.Request.Path.StartsWithSegments("/api"))
                        return "Bearer";

                    // Otherwise use cookies
                    return "Cookies";
                };
            })
            .AddJwtBearer("Bearer", options => { /* ... */ })
            .AddCookie("Cookies", options => { /* ... */ });

        builder.Services
            .AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;
            })
            .AddInMemoryIdentityResources(Config.GetIdentityResources())
            .AddInMemoryApiScopes(Config.GetApiScopes())
            .AddInMemoryClients(Config.GetClients())
            .AddAspNetIdentity<ApplicationUser>()
            .AddLicenseSummary()
            .AddProfileService<IProfileService>();

        builder.Services.AddDistributedMemoryCache();

        builder.Services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = IdentityConstants.ApplicationScheme;
            options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
            options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
        })
        .AddOpenIdConnect("Auth0Scheme", "Auth0", options =>
        {
            options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
            options.SignOutScheme = IdentityConstants.ApplicationScheme;
            options.CallbackPath = new PathString("/signin-oidc-auth0");
            options.RemoteSignOutPath = new PathString("/signout-callback-oidc-auth0");
            options.SignedOutCallbackPath = new PathString("/signout-oidc-auth0");

            options.Authority = $"https://{builder.Configuration["Auth0:Domain"]}";
            options.ClientId = builder.Configuration["Auth0:ClientId"];
            options.ClientSecret = builder.Configuration["Auth0:ClientSecret"];
            options.ResponseType = OpenIdConnectResponseType.Code;
            options.Scope.Clear();
            options.Scope.Add("openid");
            options.Scope.Add("profile");
            options.Scope.Add("email");
            options.Scope.Add("auth0-user-api-one");

            options.ClaimsIssuer = "Auth0";
            options.SaveTokens = true;
            options.UsePkce = true;
            options.GetClaimsFromUserInfoEndpoint = true;
            options.TokenValidationParameters.NameClaimType = "name";
            options.Events = new OpenIdConnectEvents
            {
                OnTokenResponseReceived = context =>
                {
                    var idToken = context.TokenEndpointResponse.IdToken;
                    return Task.CompletedTask;
                }
            };

            options.Events = new OpenIdConnectEvents
            {
                // handle the logout redirection 
                OnRedirectToIdentityProviderForSignOut = (context) =>
                {
                    var logoutUri = $"https://{builder.Configuration["Auth0:Domain"]}/v2/logout?client_id={builder.Configuration["Auth0:ClientId"]}";

                    var postLogoutUri = context.Properties.RedirectUri;
                    if (!string.IsNullOrEmpty(postLogoutUri))
                    {
                        if (postLogoutUri.StartsWith("/"))
                        {
                            // transform to absolute
                            var request = context.Request;
                            postLogoutUri = request.Scheme + "://" + request.Host + request.PathBase + postLogoutUri;
                        }
                        logoutUri += $"&returnTo={Uri.EscapeDataString(postLogoutUri)}";
                    }

                    context.Response.Redirect(logoutUri);
                    context.HandleResponse();

                    return Task.CompletedTask;
                },
                OnRedirectToIdentityProvider = context =>
                {
                    // The context's ProtocolMessage can be used to pass along additional query parameters
                    // to Auth0's /authorize endpoint.
                    // 
                    // Set the audience query parameter to the API identifier to ensure the returned Access Tokens can be used
                    // to call protected endpoints on the corresponding API.
                    context.ProtocolMessage.SetParameter("audience", "https://auth0-api1");
                    context.ProtocolMessage.AcrValues = "http://schemas.openid.net/pape/policies/2007/06/multi-factor";

                    return Task.FromResult(0);
                }
            };
        })
        //.AddId
        .AddOpenIdConnect("EntraID", "EntraID", oidcOptions =>
        {
            builder.Configuration.Bind("AzureAd", oidcOptions);
            oidcOptions.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
            oidcOptions.SignOutScheme = IdentityConstants.ApplicationScheme;

            oidcOptions.CallbackPath = new PathString("/signin-oidc");
            oidcOptions.RemoteSignOutPath = new PathString("/signout-callback-oidc");
            oidcOptions.SignedOutCallbackPath = new PathString("/signout-oidc");

            oidcOptions.Scope.Add(OpenIdConnectScope.OpenIdProfile);
            oidcOptions.Scope.Add("user.read");
            oidcOptions.Scope.Add(OpenIdConnectScope.OfflineAccess);
            oidcOptions.Authority = $"https://login.microsoftonline.com/{builder.Configuration["AzureAd:TenantId"]}/v2.0/";
            oidcOptions.ClientId = builder.Configuration["AzureAd:ClientId"];
            oidcOptions.ClientSecret = builder.Configuration["AzureAd:ClientSecret"];
            oidcOptions.ResponseType = OpenIdConnectResponseType.Code;
            oidcOptions.MapInboundClaims = false;
            oidcOptions.SaveTokens = true;
            oidcOptions.TokenValidationParameters.NameClaimType = JwtRegisteredClaimNames.Name;
            oidcOptions.TokenValidationParameters.RoleClaimType = "role";
        });

        builder.Services.AddAuthentication("Smart")
        .AddPolicyScheme("Smart", "Auto Select", options =>
        {
            options.ForwardDefaultSelector = context =>
            {
                return context.Request.Headers.ContainsKey("Authorization") ? "Bearer" : "Cookies";
            };
        });

        builder.Services.AddRazorPages();
        //.AddMicrosoftIdentityUI();

        builder.Services.AddAuthentication()
        .AddJwtBearer("some-scheme", jwtOptions =>
        {
            jwtOptions.MetadataAddress = builder.Configuration["Api:MetadataAddress"] ?? string.Empty;
            // Optional if the MetadataAddress is specified
            jwtOptions.Authority = builder.Configuration["Api:Authority"];
            jwtOptions.Audience = builder.Configuration["Api:Audience"];
            jwtOptions.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                ValidAudiences = builder.Configuration.GetSection("Api:ValidAudiences").Get<string[]>(),
                ValidIssuers = builder.Configuration.GetSection("Api:ValidIssuers").Get<string[]>()
            };

            jwtOptions.MapInboundClaims = false;
        });

        // // SP configuration - dynamic providers
        // builder.Services.AddSamlDynamicProvider(options =>
        //         {
        //             // unstorable/reusable data, such as license information and events. This will override the data stored
        //             options.Licensee =  "{Input Licensee}";
        //             options.LicenseKey =  "{Input LicenseKey}";
        //             options.SignedOutCallbackPath = "/federation/saml/slo";  //Takes a SAMLRESPONSE during SP initiated SLO
        //             options.LogSamlMessages = true;
        //             options.TimeComparisonTolerance = 300;
        //         })

        //             // Use EntityFramework store for storing identity providers
        //             //.AddIdentityProviderStore<SamlIdentityProviderStore>();

        //             // use in memory store for storing identity providers
        //             .AddInMemoryIdentityProviders(new List<IdentityProvider>
        //             {
        //                     new SamlDynamicIdentityProvider
        //                     {   

        //                         Scheme = "saml",
        //                         DisplayName = "saml",
        //                         Enabled = true,
        //                         SamlAuthenticationOptions = new Saml2pAuthenticationOptions
        //                         {
        //                             CallbackPath = "/federation/saml/signin-saml", // Duende prefixes "/federation/{scheme}/{suffix}" to all paths
        //                             SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme,
        //                             SignOutScheme = "idsrv", // main cookie user is signed into
        //                             TimeComparisonTolerance = 7200,
        //                             // The IdP you want to integrate with
        //                             IdentityProviderOptions = new IdpOptions
        //                             {
        //                                 EntityId = "https://localhost:5000",
        //                                 SigningCertificates = { new X509Certificate2("./src/Duende.FederatedGateway/idsrv3test.cer") },
        //                                 SingleSignOnEndpoint = new SamlEndpoint("https://localhost:5000/saml/sso", SamlBindingTypes.HttpRedirect),
        //                                 SingleLogoutEndpoint = new SamlEndpoint("https://localhost:5000/saml/slo", SamlBindingTypes.HttpRedirect)

        //                             },

        //                             // Details about yourself (the SP) - In This care the Federated Gateway
        //                             ServiceProviderOptions = new SpOptions
        //                             {
        //                                 EntityId = "https://localhost:5004/saml",
        //                                 MetadataPath = "/federation/saml/metadata",
        //                                 SignAuthenticationRequests = false // OPTIONAL - use if you want to sign your auth requests
        //                             }
        //                         }
        //                     }
        //             });

        //var externalLoginResult= await GetHttpContextExtensions.GetHttpContext.AuthenticateAsync("myscheme");

        builder.Services.AddIdentityServer(options =>
                   {
                       options.KeyManagement.Enabled = true;
                       options.KeyManagement.SigningAlgorithms = new[] {
                    new SigningAlgorithmOptions("RS256") {UseX509Certificate = true}
                       };

                       options.Events.RaiseErrorEvents = true;
                       options.Events.RaiseInformationEvents = true;
                       options.Events.RaiseFailureEvents = true;
                       options.Events.RaiseSuccessEvents = true;

                       // see https://docs.duendesoftware.com/identityserver/v5/fundamentals/resources/
                       options.EmitStaticAudienceClaim = true;
                   })
                   .AddSamlPlugin(options =>
                   {
                       options.Licensee = LicenseKey.Licensee;
                       options.LicenseKey = LicenseKey.Key;

                       options.WantAuthenticationRequestsSigned = false;
                   }).AddInMemoryServiceProviders(Config.GetServiceProviders());

        builder.Services.AddAuthorization(options =>
      {
          options.AddPolicy("RequireAuthenticatedUser", policy =>
          {
              policy.RequireAuthenticatedUser();
          });

          options.AddPolicy("MfaRequired", policy =>
          {
              policy.RequireAssertion(context =>
              {
                  var acrClaim = context.User.FindFirst("acr")?.Value;
                  return acrClaim == "http://schemas.openid.net/pape/policies/2007/06/multi-factor";
              });
          });

          options.AddPolicy("Auth0MfaRequired", policy =>
          {
              policy.RequireAuthenticatedUser();
              policy.RequireAssertion(context =>
              {
                  var acrClaim = context.User.FindFirst("amr")?.Value;
                  return acrClaim != null && acrClaim.Contains("mfa");
              });

          });

          options.AddPolicy("EntraIDMfaRequired", policy =>
          {
              policy.RequireAuthenticatedUser();
              policy.RequireAssertion(context =>
              {
                  var acrClaim = context.User.FindFirst("acr")?.Value;
                  return acrClaim == "http://schemas.microsoft.com/claims/multipleauthn";
              });
          });

          options.AddPolicy("ApiScope", policy =>
               {
                   policy.RequireAuthenticatedUser();
                   policy.RequireClaim("scope", "auth0-user-api-one");
               });

      });

        return builder.Build();
    }



    public static WebApplication ConfigurePipeline(this WebApplication app)
    {
        app.UseSerilogRequestLogging();

        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }

        app.UseStaticFiles();
        app.UseRouting();
        app.UseIdentityServer();
        app.UseAuthorization();

        app.MapRazorPages()
            .RequireAuthorization();

        return app;
    }
}

internal class LicenseKey
{
    internal static string Licensee = string.Empty;
    internal static string Key = string.Empty;
}

internal class ApplicationUser
{
}

