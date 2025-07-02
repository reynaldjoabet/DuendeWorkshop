using Duende.IdentityServer;
using Microsoft.AspNetCore.Authentication.Cookies;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

WebApplication app = builder.Build();
builder.Services.AddAuthentication()
    // Cookie handler for external login
    //This cookie handler is used internally by IdentityServer to temporarily store external login results during the external authentication process (e.g., Azure AD, Google). It's not for long-term user sessions.
    .AddCookie("External")
    ///IdentityServer Itself Usually Uses:

    .AddCookie("External") //for short-lived login context

    .AddCookie("Cookies") //to issue auth cookies for browser-based clients

    .AddJwtBearer()// to validate access tokens on APIs
    

    // External IdP 1: Azure AD
    .AddOpenIdConnect("aad", "Login with Azure AD", options =>
    {
        options.Authority = "https://login.microsoftonline.com/{tenant-id}/v2.0";
        options.ClientId = "{aad-client-id}";
        options.ClientSecret = "{aad-client-secret}";
        options.ResponseType = "code";
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.CallbackPath = "/signin-aad";
        options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
    })
    
    // External IdP 2: Another Duende IdentityServer
    .AddOpenIdConnect("idsrv2", "Login with External IdentityServer", options =>
    {
        options.Authority = "https://external-identityserver.com";
        options.ClientId = "your-client-id";
        options.ClientSecret = "your-client-secret";
        options.ResponseType = "code";
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.CallbackPath = "/signin-idsrv2";
        options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
    });

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

string[] summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.MapGet("/weatherforecast", () =>
{
    WeatherForecast[] forecast =  Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();
    return forecast;
})
.WithName("GetWeatherForecast");

app.Run();

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}
