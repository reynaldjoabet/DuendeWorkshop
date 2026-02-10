
namespace Extensions;

interface IRockSolidConfigurationService
{
    // System.Threading.Tasks.Task<SsoSettings> GetSsoSettingsAsync();
    RockSolidConfiguration GetConfiguration();
}