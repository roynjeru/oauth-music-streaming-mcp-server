using System.Text.Json.Serialization;

namespace src.Models
{
    public class RegisterResponse
    {
        [JsonPropertyName("client_id")]
        public string? client_id { get; set; }

        [JsonPropertyName("client_id_issued_at")]
        public long client_id_issued_at { get; set; }

        [JsonPropertyName("registration_client_uri")]
        public string? registration_client_uri { get; set; }

        [JsonPropertyName("registration_access_token")]
        public string? registration_access_token { get; set; }

        [JsonPropertyName("token_endpoint_auth_method")]
        public string? token_endpoint_auth_method { get; set; }

        [JsonPropertyName("redirect_uris")]
        public string[]? redirect_uris { get; set; }

        [JsonPropertyName("grant_types")]
        public string[]? grant_types { get; set; }

        [JsonPropertyName("response_types")]
        public string[]? response_types { get; set; }

        [JsonPropertyName("scope")]
        public string? scope { get; set; }
    }    
}