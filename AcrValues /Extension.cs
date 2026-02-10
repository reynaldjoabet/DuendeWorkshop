
using System.Net;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

public static class Extension
{
    public static void ConfigureAuthletePolicies(this AuthorizationOptions opt)
    {
       AppContext.SetSwitch("Microsoft.IdentityModel.Tokens.UseClaimsIdentityType", true);

            opt.AddPolicy(Policies.Authenticated,
                builder =>
                builder.RequireAuthenticatedUser());
            opt.AddPolicy(Policies.RequestApiKey, builder => builder.RequireAuthenticatedUser().RequireAssertion(ctx =>
                ctx.User.HasClaim(Types.IdentityAdminApiRequestApiKey, "true")));

            opt.AddPolicy(Policies.SetupWalletAccount, builder => builder.RequireAuthenticatedUser().RequireAssertion(ctx =>
               ctx.User.HasClaim(Types.SetupWalletAccount, "true")));

            opt.AddPolicy(Policies.MfaAdminFeature, builder => builder.RequireAuthenticatedUser()
            .RequireAssertion(_ => _.User.HasClaim(Types.AllowedFeatures, Features.featureMfaUserManagementTab)));

            opt.AddPolicy(Policies.ScopeWallet, builder => builder.RequireAuthenticatedUser().RequireClaim(JwtClaimTypes.Scope, Scopes.Wallet));

            //this policy requires a resource to be passed in (the subject ID)
            opt.AddPolicy(Policies.UserSelfService, builder => builder.RequireAuthenticatedUser().RequireAssertion(ctx =>
                ctx.User.HasClaim(c => c.SubjectIdEqualsResource(ctx.Resource))));

            // Policy checks if a user is not locked
            opt.AddPolicy(Policies.UserNotLocked, builder => builder.AddRequirements(new UserNotLockedRequirement()));

            // Policy checks if a user is a MFA user data bulk import job
            opt.AddPolicy(Policies.ScopeMfaUserDataImport, builder => builder.RequireAuthenticatedUser().RequireClaim(JwtClaimTypes.Scope, Scopes.MfaUserDataImport));

            opt.AddPolicy(Policies.ScopeJobsAdmin, builder => builder.RequireAuthenticatedUser().RequireClaim(JwtClaimTypes.Scope, Scopes.JobsAdmin));

            // Policy checks if token contains onboarding scope
            opt.AddPolicy(Policies.ScopeOnboarding, builder =>
            {
                builder.RequireClaim(JwtClaimTypes.Scope, Scopes.ServiceOnboarding);
            });

            opt.AddPolicy("custom-403", policy =>
            {
               policy.AddAuthenticationSchemes("Bearer");
            });

    }
        /// Returns true if the claim type is 'sub' and the value equals the resource value
        /// </summary>
        public static bool SubjectIdEqualsResource(this Claim claim, object resource)
        {
            if (!string.Equals(claim.Type, JwtClaimTypes.Subject, StringComparison.OrdinalIgnoreCase) || resource == null)
                return false;

            //wallet users are GUIDs
            //if the input is a guid try to convert the resource to a guid as well and match as GUIDs
            if (Guid.TryParse(claim.Value, out Guid subjectId) &&
                (subjectId == resource as Guid? || (Guid.TryParse(resource.ToString(), out Guid resourceGuid) && subjectId == resourceGuid)))
            {
                return true;
            }


            //GUID match was unsuccessful match trimmed/lowercase values
            if (string.Equals(claim.Value.Trim(), resource?.ToString().Trim(), StringComparison.InvariantCultureIgnoreCase))
            {
                return true;
            }

            return false;
        }

    }

internal class UserNotLockedRequirement: IAuthorizationRequirement
{
    public UserNotLockedRequirement()
    {
    }
}

internal class Scopes
{
    internal const string Wallet = "wallet";
    internal const string MfaUserDataImport = "mfa_user_data_import";
    internal const string JobsAdmin = "jobs_admin";
    internal const string ServiceOnboarding = "service_onboarding";
}

internal class JwtClaimTypes
{
    internal const string Subject = "sub";
    internal const string Scope = "scope";
}

internal class Features
{
    internal const string featureMfaUserManagementTab = "mfa_user_management_tab";
}

internal class Types
{
    internal const string IdentityAdminApiPermissions = "identity_admin_api_permissions";
    internal const string SendTempPasswordForMWalletUser = "send_temp_password_for_mwallet_user";
    internal const string SetupWalletAccount = "setup_wallet_account";
    internal static string AllowedFeatures= nameof(AllowedFeatures);
    internal static string IdentityAdminApiRequestApiKey= nameof(IdentityAdminApiRequestApiKey);
}

internal class Policies
{
    internal static string Authenticated= nameof(Authenticated);

    internal static string ApiRead = nameof(ApiRead);

    internal static string ApiWrite = nameof(ApiWrite);

    internal static string RequestApiKey = nameof(RequestApiKey);

    internal static string SetupWalletAccount = nameof(SetupWalletAccount);

    internal static string MfaAdminFeature = nameof(MfaAdminFeature);

    internal static string ScopeWallet = nameof(ScopeWallet);

    internal static string UserSelfService = nameof(UserSelfService);

    internal static string IdentityAdminUser = nameof(IdentityAdminUser);

    internal static string UserNotLocked = nameof(UserNotLocked);

    internal static string ScopeMfaUserDataImport = nameof(ScopeMfaUserDataImport);

    internal static string ScopeJobsAdmin = nameof(ScopeJobsAdmin);

    internal static string ScopeOnboarding = nameof(ScopeOnboarding);

    internal static string MWalletUser = nameof(MWalletUser);
 
}