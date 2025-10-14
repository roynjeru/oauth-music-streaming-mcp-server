using System.Text.Json.Serialization;

namespace src.Models
{
    public class SpotifyTokenExchangeRequest
    {
        [JsonPropertyName("access_token")]
        public required string AccessToken { get; set; }
        [JsonPropertyName("refresh_token")]
        public required string RefreshToken { get; set; }
    }
}