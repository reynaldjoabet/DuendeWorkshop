
// using System.Security.Claims;
// using Microsoft.IdentityModel.Protocols.OpenIdConnect;
// using Microsoft.Owin.Security.Notifications;
// using Microsoft.Owin.Security.OpenIdConnect;

// public class ProgramDuende
// {
//     public static void Main(string[] args)
//     {
//         WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

//         // Add services to the container.
//         builder.Services.AddRazorPages();

//         builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
//         builder.Services.AddTransient<StepUpHandler>();
//         builder.Services.AddOpenIdConnectAccessTokenManagement();
//         builder.Services.AddUserAccessTokenHttpClient("StepUp",
//             configureClient: static client =>
//             {
//                 client.BaseAddress = new Uri("https://localhost:7001/step-up/");
//             }).AddHttpMessageHandler<StepUpHandler>();

//         builder.Services.AddAuthentication(static opt =>
//             {
//                 opt.DefaultScheme = "cookie";
//                 opt.DefaultChallengeScheme = "oidc";
//             })
//             .AddCookie("cookie")
//             .AddOpenIdConnect("oidc", static opt =>
//             {
//                 opt.Authority = "https://localhost:5001";
//                 opt.ClientId = "step-up";
//                 opt.ClientSecret = "secret";
//                 opt.ResponseType = "code";
//                 opt.Scope.Add("scope1");
//                 opt.ClaimActions.Remove("acr");
//                 opt.SaveTokens = true;
//                 opt.GetClaimsFromUserInfoEndpoint = true;
//                 opt.MapInboundClaims = false;
//                 opt.TokenValidationParameters.NameClaimType = "name";
//                 opt.TokenValidationParameters.RoleClaimType = "role";

//                 opt.Events.OnRedirectToIdentityProvider = static ctx =>
//                 {
//                     if (ctx.Properties.Items.ContainsKey("acr_values"))
//                     {
//                         ctx.ProtocolMessage.AcrValues = ctx.Properties.Items["acr_values"];
//                     }
//                     if (ctx.Properties.Items.ContainsKey("max_age"))
//                     {
//                         ctx.ProtocolMessage.MaxAge = ctx.Properties.Items["max_age"];
//                     }
//                     return Task.CompletedTask;
//                 };

//                 opt.Events.OnRemoteFailure = static ctx =>
//                 {
//                     if (ctx.Failure?.Data.Contains("error") ?? false)
//                     {
//                         string? error = ctx.Failure.Data["error"] as string;
//                         // if (error == IdentityModel.OidcConstants.AuthorizeErrors.UnmetAuthenticationRequirements)
//                         // {
//                         //     ctx.HandleResponse();
//                         //     ctx.Response.Redirect("/MfaDeclined");
//                         // }
//                     }
//                     return Task.CompletedTask;
//                 };
//             });

//         WebApplication app = builder.Build();

//         // Configure the HTTP request pipeline.
//         if (!app.Environment.IsDevelopment())
//         {
//             app.UseExceptionHandler("/Error");
//             // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
//             app.UseHsts();
//         }

//         app.UseHttpsRedirection();
//         app.UseStaticFiles();

//         app.UseRouting();

//         app.UseAuthentication();
//         app.UseAuthorization();

//         app.MapRazorPages();

//             app.Run();
//         }

//         private static Task HandleSecurityTokenValidatedNotification(SecurityTokenValidatedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context)
//         {
//             context.AuthenticationTicket.Identity.AddClaim(new Claim(Constants.ClaimTypes.IdToken, context.ProtocolMessage.IdToken));
//             return Task.FromResult(0);
//         }

//         private static Task HandleRedirectToIdentityProviderNotification(Microsoft.Owin.Security.Notifications.RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context)
//         {
//             context.ProtocolMessage.RedirectUri = context.Request.Uri.GetLeftPart(UriPartial.Authority);
//             if (context.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
//             {
//                 var idToken = context.OwinContext.Authentication.User.FindFirst(Constants.ClaimTypes.IdToken);
//                 if (idToken != null)
//                 {
//                     context.ProtocolMessage.IdTokenHint = idToken.Value;
//                 }
//             }
//             if (context.ProtocolMessage.RequestType == OpenIdConnectRequestType.Authentication)
//             {
//                 context.ProtocolMessage.RedirectUri += context.Options.CallbackPath.ToString();
//                 var idp = context.OwinContext.Get<string>("idp");
//                 if (string.IsNullOrWhiteSpace(idp) == false)
//                 {
//                     context.ProtocolMessage.AcrValues = "idp:" + idp;
//                 }
//             }
//             return Task.FromResult(0);
//         }
    
//     }
