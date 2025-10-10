using System.Text.Json.Serialization;

namespace src.Models
{
    // Dynamic client registration DTOs and storage model
    public class RegisterRequest
    {
        [JsonPropertyName("redirect_uris")]
        public string[]? redirect_uris { get; set; }

        [JsonPropertyName("client_name")]
        public string? client_name { get; set; }

        [JsonPropertyName("token_endpoint_auth_method")]
        public string? token_endpoint_auth_method { get; set; }

        [JsonPropertyName("grant_types")]
        public string[]? grant_types { get; set; }

        [JsonPropertyName("response_types")]
        public string[]? response_types { get; set; }

        [JsonPropertyName("scope")]
        public string? scope { get; set; }

        public override string ToString()
        {
            return System.Text.Json.JsonSerializer.Serialize(this);
        }
    }
}