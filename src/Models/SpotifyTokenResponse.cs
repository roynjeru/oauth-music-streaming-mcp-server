
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
        public string? RefreshToken { get; init; }

        [JsonPropertyName("scope")]
        public string? Scope { get; init; }

        public override string ToString()
        {
            return $"AccessToken: {AccessToken}, TokenType: {TokenType}, ExpiresIn: {ExpiresIn}, RefreshToken: {RefreshToken}, Scope: {Scope}";
        }
    }
}