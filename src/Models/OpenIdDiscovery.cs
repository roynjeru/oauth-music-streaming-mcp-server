namespace src.Models
{
    public sealed class OpenIdDiscovery
    {
    public string issuer { get; set; } = default!;
    public string jwks_uri { get; set; } = default!;
    public string authorization_endpoint { get; set; } = default!;
    public string token_endpoint { get; set; } = default!;

    public string[] response_types_supported { get; set; } = Array.Empty<string>();
    public string[] response_modes_supported { get; set; } = Array.Empty<string>();
    public string[] grant_types_supported { get; set; } = Array.Empty<string>();
    public string[] code_challenge_methods_supported { get; set; } = Array.Empty<string>();
    public string[] subject_types_supported { get; set; } = Array.Empty<string>();
    public string[] id_token_signing_alg_values_supported { get; set; } = Array.Empty<string>();
    public string[] token_endpoint_auth_methods_supported { get; set; } = Array.Empty<string>();
    public string[] scopes_supported { get; set; } = Array.Empty<string>();
    public string[] claims_supported { get; set; } = Array.Empty<string>();
    }
}