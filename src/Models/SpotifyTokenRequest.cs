

using System.Text.Json.Serialization;

namespace src.Models
{
    public sealed class SpotifyTokenRequest
    {
        [JsonPropertyName("grant_type")]
        public required string GrantType { get; init; }

        [JsonPropertyName("code")]
        public required string Code { get; init; }

        [JsonPropertyName("redirect_uri")]
        public required string RedirectUri { get; init; }

        [JsonPropertyName("client_id")]
        public required string ClientId { get; init; }

        [JsonPropertyName("code_verifier")]
        public required string CodeVerifier { get; init; }
    }
}