
using System.Text.Json.Serialization;

namespace src.Models
{
    public sealed class SpotifyTokenResponse
    {
        [JsonPropertyName("access_token")]
        public required string AccessToken { get; init; }

        [JsonPropertyName("token_type")]
        public required string TokenType { get; init; }

        [JsonPropertyName("expires_in")]
        public required int ExpiresIn { get; init; }

        [JsonPropertyName("refresh_token")]
        public string? RefreshToken { get; set; }

        [JsonPropertyName("scope")]
        public string? Scope { get; init; }
        private DateTimeOffset? ExpiresAt { get; set; }

        public override string ToString()
        {
            return $"AccessToken: {AccessToken}, TokenType: {TokenType}, ExpiresIn: {ExpiresIn}, RefreshToken: {RefreshToken}, Scope: {Scope}";
        }

        public void SetExpiry()
        {
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(ExpiresIn);
        }

        public DateTimeOffset GetExpiry()
        {
            return ExpiresAt ?? DateTimeOffset.UtcNow.AddSeconds(-5);
        }
    }
}