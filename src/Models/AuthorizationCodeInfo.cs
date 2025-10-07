using System.Text.Json.Serialization;

namespace src.Models;

/// <summary>
/// Represents authorization code information for OAuth flow.
/// </summary>
internal sealed class AuthorizationCodeInfo
{
    /// <summary>
    /// Gets or sets the client ID associated with this authorization code.
    /// </summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// Gets or sets the client redirect URI associated with this authorization code.
    /// </summary>
    public required string ClientRedirectUri { get; init; }

    public string SpofityRedirectUri { get; init; } = string.Empty;

    /// <summary>
    /// Gets or sets the code challenge associated with this authorization code (for PKCE).
    /// </summary>
    public required string CodeChallenge { get; init; }

    /// <summary>
    /// Gets or sets the list of scopes approved for this authorization code.
    /// </summary>
    public List<string> Scope { get; init; } = [];

    /// <summary>
    /// Gets or sets the optional resource URI this authorization code is for.
    /// </summary>
    public Uri? Resource { get; init; }

    public string SpotifyCodeVerifier { get; init; } = string.Empty;

    public string ClientState { get; init; } = string.Empty;

    public string SpotifyState { get; init; } = string.Empty;

    public string SpotifyAuthCode { get; set; } = string.Empty;
}