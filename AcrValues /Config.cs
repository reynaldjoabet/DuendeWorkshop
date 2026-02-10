
using Duende.IdentityServer.Models;
using System.Collections.Generic;
using Rsk.Saml;
using Rsk.Saml.Models;
using ServiceProvider = Rsk.Saml.Models.ServiceProvider;
using Duende.IdentityServer;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.AspNetCore.WebSockets;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.AspNetCore.StaticAssets;
using Microsoft.AspNetCore.Session;
using Microsoft.AspNetCore.Server;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.AspNetCore.ResponseCaching;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.HostFiltering;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.AspNetCore.OutputCaching;
using Microsoft.AspNetCore.Owin;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.LoggingExtensions;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Validators;
using Microsoft.Identity.Abstractions;
using Microsoft.Identity.Client;
using Microsoft.Identity.Web;
using Microsoft.Extensions.Azure;
using Microsoft.Extensions.Caching;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyModel;
using Microsoft.Extensions.Diagnostics;
using Microsoft.Extensions.FileSystemGlobbing;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using Microsoft.DotNet.PlatformAbstractions;
using Microsoft.OpenApi.Models;
public static class Config
{
    // All ApiScopes
    public static IEnumerable<ApiScope> GetApiScopes() =>
        new[]
        {
            // billing
            new ApiScope("billing.invoices.read", "List & retrieve invoices"),
            new ApiScope("billing.invoices.create", "Create invoices"),
            new ApiScope("billing.invoices.update", "Update invoices"),
            new ApiScope("billing.invoices.manage", "Manage invoices (admin)"),
            new ApiScope("billing.invoices.cancel", "Cancel invoices"),
            new ApiScope("billing.invoices.adjust", "Adjust invoices"),
            new ApiScope("billing.invoices.reopen", "Reopen invoices"),
            new ApiScope("billing.audit.read", "Read billing audit logs"),
            new ApiScope("billing.audit.export", "Export billing audit logs"),

            // payments
            new ApiScope("payments.transactions.read", "List & retrieve transactions"),
            new ApiScope("payments.transactions.create", "Initiate a payment"),
            new ApiScope("payments.transactions.capture", "Capture an authorized payment"),
            new ApiScope("payments.transactions.void", "Void an uncaptured payment"),
            new ApiScope("payments.transactions.refund", "Refund a settled payment"),
            new ApiScope("payments.authorizations.read", "Read authorization status"),
            new ApiScope("payments.authorizations.create", "Create a payment authorization"),
            new ApiScope("payments.methods.read", "List stored payment methods"),
            new ApiScope("payments.methods.create", "Add payment method"),
            new ApiScope("payments.methods.update", "Update payment method metadata"),
            new ApiScope("payments.methods.delete", "Remove payment method"),
            new ApiScope("payments.methods.manage", "Manage payment methods (admin)"),
            new ApiScope("payments.settlements.read", "Read settlement batches"),
            new ApiScope("payments.settlements.close", "Close settlement batch"),
            new ApiScope("payments.disputes.read", "Read disputes/chargebacks"),
            new ApiScope("payments.disputes.respond", "Submit dispute evidence"),

            // accounts & initiations
            new ApiScope("accounts.read", "Read accounts list and metadata"),
            new ApiScope("accounts.balances.read", "Read account balances"),
            new ApiScope("accounts.transactions.read", "Read account transaction history"),
            new ApiScope("accounts.transactions.export", "Export transactions"),
            new ApiScope("payments.initiations.create", "Initiate bank payment (PIS)"),
            new ApiScope("payments.initiations.status.read", "Read payment initiation status"),
            new ApiScope("payments.initiations.cancel", "Cancel pending payment"),
            new ApiScope("beneficiaries.read", "Read beneficiaries/payees"),
            new ApiScope("beneficiaries.create", "Add new beneficiary"),
            new ApiScope("beneficiaries.delete", "Remove beneficiary"),

            // customers
            new ApiScope("customers.profile.read", "Read customer profile"),
            new ApiScope("customers.profile.update", "Update non-sensitive profile fields"),
            new ApiScope("customers.identity.read", "Read verified identity attributes"),
            new ApiScope("customers.identity.verify", "Perform identity verification"),
            new ApiScope("customers.contacts.read", "Read contact details"),
            new ApiScope("customers.contacts.update", "Update contact details"),

            // audit / risk / limits
            new ApiScope("audit.events.read", "Read security/compliance audit logs"),
            new ApiScope("audit.events.export", "Export audit logs"),
            new ApiScope("risk.scores.read", "Read risk/fraud scores"),
            new ApiScope("risk.rules.read", "Read fraud rules"),
            new ApiScope("risk.rules.manage", "Manage fraud rules (admin)"),
            new ApiScope("limits.read", "Read transaction limits"),
            new ApiScope("limits.update", "Update limits (admin/compliance)"),

            // ledger / treasury
            new ApiScope("ledger.entries.read", "Read ledger entries"),
            new ApiScope("ledger.entries.create", "Create ledger entries"),
            new ApiScope("ledger.entries.adjust", "Adjust ledger entries (restricted)"),
            new ApiScope("treasury.balances.read", "Read treasury balances"),
            new ApiScope("treasury.transfers.create", "Create internal fund transfers"),

            // reports
            new ApiScope("reports.financial.read", "Read financial reports"),
            new ApiScope("reports.regulatory.read", "Read regulatory reports"),
            new ApiScope("reports.exports.create", "Generate report exports"),
            new ApiScope("reports.exports.read", "Download generated exports"),

            // subscriptions & plans
            new ApiScope("subscriptions.plans.read", "Read plans"),
            new ApiScope("subscriptions.plans.create", "Create plans"),
            new ApiScope("subscriptions.plans.update", "Update plans"),
            new ApiScope("subscriptions.plans.archive", "Archive plans"),
            new ApiScope("subscriptions.subscriptions.read", "Read subscriptions"),
            new ApiScope("subscriptions", "General subscriptions access")
        };

    // ApiResources group scopes by logical API name.  Consumers can require resource scopes.
    public static IEnumerable<ApiResource> GetApiResources() =>
        new[]
        {
            new ApiResource("billing")
            {
                Scopes = {
                    "billing.invoices.read",
                    "billing.invoices.create",
                    "billing.invoices.update",
                    "billing.invoices.manage",
                    "billing.invoices.cancel",
                    "billing.invoices.adjust",
                    "billing.invoices.reopen",
                    "billing.audit.read",
                    "billing.audit.export"
                },
                RequireResourceIndicator = true
            },

            new ApiResource("payments")
            {
                Scopes = {
                    "payments.transactions.read",
                    "payments.transactions.create",
                    "payments.transactions.capture",
                    "payments.transactions.void",
                    "payments.transactions.refund",
                    "payments.authorizations.read",
                    "payments.authorizations.create",
                    "payments.methods.read",
                    "payments.methods.create",
                    "payments.methods.update",
                    "payments.methods.delete",
                    "payments.methods.manage",
                    "payments.settlements.read",
                    "payments.settlements.close",
                    "payments.disputes.read",
                    "payments.disputes.respond",
                    "payments.initiations.create",
                    "payments.initiations.status.read",
                    "payments.initiations.cancel"
                },
                ApiSecrets = {
                    new Duende.IdentityServer.Models.Secret("payments_secret".Sha256())
                },
                UserClaims = { "role" },
                RequireResourceIndicator = true
            },

            new ApiResource("accounts")
            {
                Scopes = {
                    "accounts.read",
                    "accounts.balances.read",
                    "accounts.transactions.read",
                    "accounts.transactions.export",
                    "beneficiaries.read",
                    "beneficiaries.create",
                    "beneficiaries.delete"
                },
                RequireResourceIndicator = true
            },

            new ApiResource("customers")
            {
                Scopes = {
                    "customers.profile.read",
                    "customers.profile.update",
                    "customers.identity.read",
                    "customers.identity.verify",
                    "customers.contacts.read",
                    "customers.contacts.update"
                },
                ApiSecrets = {
                    new Duende.IdentityServer.Models.Secret("customers_secret".Sha256())
                },
                RequireResourceIndicator = true
            },

            new ApiResource("audit")
            {
                Scopes = {
                    "audit.events.read",
                    "audit.events.export"
                },
                RequireResourceIndicator = true
            },

            new ApiResource("risk")
            {
                Scopes = {
                    "risk.scores.read",
                    "risk.rules.read",
                    "risk.rules.manage"
                },
                RequireResourceIndicator = true
            },

            new ApiResource("limits")
            {
                Scopes = {
                    "limits.read",
                    "limits.update"
                },
                RequireResourceIndicator = true
            },

            new ApiResource("ledger")
            {
                Scopes = {
                    "ledger.entries.read",
                    "ledger.entries.create",
                    "ledger.entries.adjust"
                },
                RequireResourceIndicator = true
            },

            new ApiResource("treasury")
            {
                Scopes = {
                    "treasury.balances.read",
                    "treasury.transfers.create"
                }
            },

            new ApiResource("reports")
            {
                Scopes = {
                    "reports.financial.read",
                    "reports.regulatory.read",
                    "reports.exports.create",
                    "reports.exports.read"
                },
                ApiSecrets = {
                    new Duende.IdentityServer.Models.Secret("reports_secret".Sha256())
                },
                RequireResourceIndicator = true
            },

            new ApiResource("subscriptions")
            {
                Scopes = {
                    "subscriptions.plans.read",
                    "subscriptions.plans.create",
                    "subscriptions.plans.update",
                    "subscriptions.plans.archive",
                    "subscriptions.subscriptions.read",
                    "subscriptions"
                },
                ApiSecrets = {
                    new Duende.IdentityServer.Models.Secret("subscriptions_secret".Sha256())
                },
                RequireResourceIndicator = true
            }
        };

    public static IEnumerable<IdentityResource> GetIdentityResources() =>
        new[]
        {
            new IdentityResources.OpenId(),
            new IdentityResources.Profile(),
            new IdentityResources.Email(),
            new IdentityResource("roles", "User roles", new[] { "role" })
        };    

    public static IEnumerable<Client> GetClients() =>
        new[]
        {
            new Client
            {
                ClientId = "billing_service_client",
                ClientName = "Billing Service Client",
                AllowedGrantTypes = GrantTypes.ClientCredentials,
                ClientSecrets = { new Duende.IdentityServer.Models.Secret("billing_service_secret".Sha256()) },
                AllowedScopes = { "billing.invoices.read", "billing.invoices.create", "billing.audit.read" },
                ProtocolType = "oidc" ,
                RedirectUris = { "https://billingservice.example.com/signin-oidc" },
                PostLogoutRedirectUris = { "https://billingservice.example.com/signout-callback-oidc"},
                AllowOfflineAccess = true,
                RequireClientSecret = false,
                RequirePkce = true,
                RequireDPoP= true,
                DPoPValidationMode=DPoPTokenExpirationValidationMode.Nonce,
                FrontChannelLogoutUri = "https://billingservice.example.com/signout-oidc",
                FrontChannelLogoutSessionRequired = true,
                BackChannelLogoutUri = "https://billingservice.example.com/backchannel-logout",
                BackChannelLogoutSessionRequired = true,
                PushedAuthorizationLifetime= 300,
                RequirePushedAuthorization= true,
                IdentityProviderRestrictions = { "local", "externalidp" },
                IncludeJwtId= true,
                AccessTokenType = AccessTokenType.Jwt,
                AllowAccessTokensViaBrowser= false,
                AlwaysSendClientClaims= false,
                ClientClaimsPrefix= "billing_",
                UserSsoLifetime= 3600,

            },
            new Client
            {
                ClientId = "payments_service_client",
                ClientName = "Payments Service Client",
                AllowedGrantTypes = GrantTypes.ClientCredentials,
                ClientSecrets = { new Duende.IdentityServer.Models.Secret("payments_service_secret".Sha256()) },
                AllowedScopes = { "payments.transactions.read", "payments.transactions.create", "payments.methods.read" }
            }, new Client
            {
                ClientId = "https://localhost:5002/saml",
                ClientName = "RSK SAML2P Test Client - Multiple SP",
                ProtocolType = IdentityServerConstants.ProtocolTypes.Saml2p,
                AllowedScopes = {"openid", "profile"}
            },

            new Client
            {
                ClientId = "accounts_service_client",
                ClientName = "Accounts Service Client",
                AllowedGrantTypes = GrantTypes.ClientCredentials,
                ClientSecrets = { new Duende.IdentityServer.Models.Secret("accounts_service_secret".Sha256()) },
                AllowedScopes = { "accounts.read", "accounts.balances.read", "beneficiaries.read" },

            },
            new Client
            {
                ClientId = "customers_service_client",
                ClientName = "Customers Service Client",
                AllowedGrantTypes = GrantTypes.ClientCredentials,
                ClientSecrets = { new Duende.IdentityServer.Models.Secret("customers_service_secret".Sha256()) },
                AllowedScopes = { "customers.profile.read", "customers.identity.read", "customers.contacts.read" },
                EnableLocalLogin = false,
                IdentityProviderRestrictions = ["AdminEntraID"]
            },
            new Client
            {
                ClientId = "reports_service_client",
                ClientName = "Reports Service Client",
                AllowedGrantTypes = GrantTypes.ClientCredentials,
                ClientSecrets = { new Duende.IdentityServer.Models.Secret("reports_service_secret".Sha256()) },
                AllowedScopes = { "reports.financial.read", "reports.exports.create" }
            },
            new Client
            {
                ClientId = "subscriptions_service_client",
                ClientName = "Subscriptions Service Client",
                AllowedGrantTypes = GrantTypes.ClientCredentials,
                ClientSecrets = { new Duende.IdentityServer.Models.Secret("subscriptions_service_secret".Sha256()) },
                AllowedScopes = { "subscriptions.plans.read", "subscriptions.subscriptions.read" },
                // show/hide the local authentication screen
                EnableLocalLogin = false,

                // federated authentication options to display
                // empty displays all
                IdentityProviderRestrictions = ["AdminEntraID"]
            },
            
        };

    //dentityProviderName

    public static IEnumerable<IdentityProviderName> GetIdentityProviderNames() =>
          new[]
            {
                new IdentityProviderName
                {
                    Scheme = "AdminEntraID",
                    DisplayName = "Admin Entra ID",
                    Enabled = true
                },
                new IdentityProviderName
                {
                    Scheme = "externalidp",
                    DisplayName = "External Identity Provider",
                    Enabled = true
                },
                new IdentityProviderName
                {
                    Scheme = "local",
                    DisplayName = "Local Account",
                    Enabled = true
                },
                new IdentityProviderName
                {
                    Scheme = "Google",
                    DisplayName = "Google",
                    Enabled = false
                },
                new IdentityProviderName
                {
                    Scheme = "Facebook",
                    DisplayName = "Facebook",
                    Enabled = false
                },
                new IdentityProviderName
                {
                    Scheme = "Twitter",
                    DisplayName = "Twitter",
                    Enabled = false
                }
            };   

      //OidcProvider

    public static IEnumerable<OidcProvider> GetOidcProviders() =>
          new[]
            {
                new OidcProvider
                {
                    Scheme = "AdminEntraID",
                    DisplayName = "Admin Entra ID",
                    Enabled = true,
                    Type="oidc",
                     //The response type. Defaults to "id_token".
                    ResponseType = "code",
                    Authority = "https://login.microsoftonline.com/{tenantid}/v2.0",
                    ClientId = "your_admin_entra_id_client_id",
                    ClientSecret = "your_admin_entra_id_client_secret",
                    GetClaimsFromUserInfoEndpoint = true,
                    Scope = "openid profile email",
                    UsePkce = true
                },
                new OidcProvider
                {
                    Scheme = "externalidp",
                    DisplayName = "External Identity Provider",
                    Enabled = true,
                    Type="oidc",
                    ResponseType = "code",
                    Authority = "https://externalidp.example.com",
                    ClientId = "your_external_idp_client_id",
                    ClientSecret = "your_external_idp_client_secret",
                    GetClaimsFromUserInfoEndpoint = true,
                    Scope = "openid profile email",
                    UsePkce = true
                },
                new OidcProvider
                {
                    Scheme = "local",
                    DisplayName = "Local Account",
                    Enabled = true,
                    Type="local"
                }
            }; 

          public static IEnumerable<ServiceProvider> GetServiceProviders()
    {
        return new[]
        {
            new ServiceProvider
            {
                EntityId = "https://localhost:5002/saml",
                AssertionConsumerServices =
                {
                    new Service(SamlConstants.BindingTypes.HttpPost , "https://localhost:5002/saml/sso"),
                    new Service(SamlConstants.BindingTypes.HttpPost, "https://localhost:5002/signin-saml-3")
                },
                SingleLogoutServices =
                {
                    new Service(SamlConstants.BindingTypes.HttpRedirect , "https://localhost:5002/saml/slo")
                }
            },
             new ServiceProvider()
        {
            EntityId = "https://localhost:5002",
            AssertionConsumerServices = new List<Service>()
            {
                new Service(SamlConstants.BindingTypes.HttpPost, "https://localhost:5002/signin-saml")
            },
            SingleLogoutServices = new List<Service>()
            {
              new Service(SamlConstants.BindingTypes.HttpPost, "https://localhost:5002/signout-saml")  
            },
            SigningCertificates = new List<X509Certificate2>()
            {
                X509CertificateLoader.LoadCertificateFromFile("Resources/testclient.cer")
            }
        },
        new ServiceProvider()
        {
          EntityId = "https://localhost:5003",
          AssertionConsumerServices = new List<Service>()
          {
              new Service(SamlConstants.BindingTypes.HttpPost, "https://localhost:5003/signin-saml")
          },
          SingleLogoutServices = new List<Service>()
          {
            new Service(SamlConstants.BindingTypes.HttpPost, "https://localhost:5003/signout-saml")  
          },
          SigningCertificates = new List<X509Certificate2>()
          {
              X509CertificateLoader.LoadCertificateFromFile("Resources/testclient.cer")
          }
        },
        new ServiceProvider()
        {
            EntityId = "https://localhost:5004",
            AssertionConsumerServices = new List<Service>()
            {
                new Service(SamlConstants.BindingTypes.HttpPost, "https://localhost:5004/signin-saml")
            },
            SingleLogoutServices = new List<Service>()
            {
                new Service(SamlConstants.BindingTypes.HttpPost, "https://localhost:5004/signout-saml")  
            },
            SigningCertificates = new List<X509Certificate2>()
            {
                //X509CertificateLoader
                X509CertificateLoader.LoadCertificateFromFile("Resources/testclient.cer")
            }
        }
        };
    }           
}
