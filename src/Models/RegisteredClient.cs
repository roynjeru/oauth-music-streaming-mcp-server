using System.Text.Json.Serialization;

namespace src.Models
{
    public class RegisteredClient
    {
        public string? ClientId { get; set; }
        public string[]? RedirectUris { get; set; }
        public string? ClientName { get; set; }
        public string? TokenEndpointAuthMethod { get; set; }
        public string[]? GrantTypes { get; set; }
        public string[]? ResponseTypes { get; set; }
        public string? Scope { get; set; }
        public string? RegistrationAccessToken { get; set; }
        public long ClientIdIssuedAt { get; set; }
        public string? RegistrationClientUri { get; set; }
    }
}