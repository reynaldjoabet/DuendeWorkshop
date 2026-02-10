
namespace Extensions;
public static class AuthenticationAuthorizationExtensions
{
public static void AddSso( this IServiceCollection services, IConfiguration configuration)
{
    using var scope = services.BuildServiceProvider().CreateScope();

    var rockSolidConfigurationService= scope.ServiceProvider.GetRequiredService<IRockSolidConfigurationService>();

    var logger= scope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("AuthenticationAuthorizationExtensions");
    var rockSolidConfiguration= rockSolidConfigurationService.GetConfiguration();

        try
        {
            if(rockSolidConfiguration.Enabled)
            {
                logger.LogInformation("Configuring RockSolid SSO authentication");

                services.AddAuthentication()
                    .AddOpenIdConnect("RockSolid", "RockSolid SSO", options =>
                    {
                        options.Authority = rockSolidConfiguration.Authority;
                        options.ClientId = rockSolidConfiguration.ClientId;
                        options.ClientSecret = rockSolidConfiguration.ClientSecret;
                        options.ResponseType = "code";
                        options.SaveTokens = true;
                        options.GetClaimsFromUserInfoEndpoint = true;

                        foreach (var scope in rockSolidConfiguration.Scopes)
                        {
                            options.Scope.Add(scope);
                        }

                    });
            }
            else
            {
                logger.LogInformation("RockSolid SSO authentication is disabled");
            }
        } catch (Exception ex)
        {
            logger.LogError(ex, "Error configuring RockSolid SSO authentication");
            throw;
        }

}

public static void AddRockSolidKnowledgeComponents(this IServiceCollection services, RockSolidConfiguration configuration)
{
        services.AddDynamicProviders(opt =>
        {
            opt.Licensee="YourLicensee";
            opt.LicenseKey="YourLicenseKey";
        }).AddOpenIdConnect()
        .AddSaml(options =>
        {
            options.CallbackPath = "/signin-saml";
            options.SignInScheme = "Cookies";
        })
        ;


}

}