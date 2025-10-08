using Azure.Monitor.OpenTelemetry.AspNetCore;
using System.Collections.Concurrent;
using System.Reflection;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using src.Helpers;
using src.Models;
using src.Services;

var builder = WebApplication.CreateBuilder(args);

// get URL and port from environment variable if set
int port = int.Parse(Environment.GetEnvironmentVariable("WEBSITE_PORT"));

var spotifyAuthUrl = "https://accounts.spotify.com/authorize";
var spotifyScopes = "user-read-private user-read-email streaming user-read-playback-state user-modify-playback-state";
var spotifyClientId = "04e740f554cc46469e3645a37b861a75";
var spotifyRedirectUri = "http://127.0.0.1:8080/spotify-callback";

// Port 5000 is used by tests and port 7071 is used by the ProtectedMcpServer sample
// string[] ValidResources = ["http://localhost:5000/", "http://localhost:7071/"];

ConcurrentDictionary<string, AuthorizationCodeInfo> _authCodes = new();
ConcurrentDictionary<string, string> _mcpCodeMap = new();
ConcurrentDictionary<string, TokenInfo> _tokens = new();
ConcurrentDictionary<string, ClientInfo> _clients = new();

RSA _rsa = RSA.Create(2048);
string _keyID = Guid.NewGuid().ToString();

builder.Services.AddRoutingCore();
builder.Services.ConfigureHttpJsonOptions(jsonOptions =>
{
    jsonOptions.SerializerOptions.TypeInfoResolverChain.Add(OAuthJsonContext.Default);
});
builder.Logging.AddConsole();
builder.Services.AddHttpClient();
builder.Services.AddTransient<HttpService>();

// configure OpenTelemetry
builder.Services.AddOpenTelemetry().UseAzureMonitor();

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

var app = builder.Build();

app.UseRouting();
app.UseEndpoints(_ => { });

// The MCP spec tells the client to use /.well-known/oauth-authorization-server but AddJwtBearer looks for
// /.well-known/openid-configuration by default. To make things easier, we support both with the same response
// which seems to be common. Ex. https://github.com/keycloak/keycloak/pull/29628
//
// The requirements for these endpoints are at https://www.rfc-editor.org/rfc/rfc8414 and
// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata respectively.
// They do differ, but it's close enough at least for our current testing to use the same response for both.
// See https://gist.github.com/localden/26d8bcf641703c08a5d8741aa9c3336c
string[] metadataEndpoints = ["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"];
foreach (var metadataEndpoint in metadataEndpoints)
{
    // OAuth 2.0 Authorization Server Metadata (RFC 8414)
    app.MapGet(metadataEndpoint, (HttpContext context, HttpRequest request) =>
    {
        string requestUrl = $"{request.Scheme}://{request.Host}";
        var obj = new { context, request };
        var metadata = new OAuthServerMetadata
        {
            Issuer = requestUrl, // env_url,
            AuthorizationEndpoint = $"{requestUrl}/authorize",
            TokenEndpoint = $"{requestUrl}/token",
            JwksUri = $"{requestUrl}/.well-known/jwks.json",
            ResponseTypesSupported = ["code"],
            SubjectTypesSupported = ["public"],
            IdTokenSigningAlgValuesSupported = ["RS256"],
            ScopesSupported = ["openid", "profile", "email", "mcp:tools"],
            TokenEndpointAuthMethodsSupported = ["client_secret_post"],
            ClaimsSupported = ["sub", "iss", "name", "email", "aud"],
            CodeChallengeMethodsSupported = ["S256"],
            GrantTypesSupported = ["authorization_code", "refresh_token"],
            IntrospectionEndpoint = $"{requestUrl}/introspect",
            RegistrationEndpoint = $"{requestUrl}/register"
        };

        return Results.Ok(metadata);
    });
}

// Authorize endpoint
app.MapGet("/authorize", (
    [FromQuery] string client_id,
    [FromQuery] string? redirect_uri,
    [FromQuery] string response_type,
    [FromQuery] string code_challenge,
    [FromQuery] string code_challenge_method,
    [FromQuery] string? scope,
    [FromQuery] string? state,
    [FromQuery] string? resource, HttpRequest request) =>
{
    // Validate client
    // if (!_clients.TryGetValue(client_id, out var client))
    // {
    //     return Results.BadRequest(new OAuthErrorResponse
    //     {
    //         Error = "invalid_client",
    //         ErrorDescription = "Client not found"
    //     });
    // }

    // Validate redirect_uri
    // if (string.IsNullOrEmpty(redirect_uri))
    // {
    //     if (client.RedirectUris.Count == 1)
    //     {
    //         redirect_uri = client.RedirectUris[0];
    //     }
    //     else
    //     {
    //         return Results.BadRequest(new OAuthErrorResponse
    //         {
    //             Error = "invalid_request",
    //             ErrorDescription = "redirect_uri is required when client has multiple registered URIs"
    //         });
    //     }
    // }
    // else if (!client.RedirectUris.Contains(redirect_uri))
    // {
    //     return Results.BadRequest(new OAuthErrorResponse
    //     {
    //         Error = "invalid_request",
    //         ErrorDescription = "Unregistered redirect_uri"
    //     });
    // }

    // Validate response_type
    if (response_type != "code")
    {
        return Results.Redirect($"{redirect_uri}?error=unsupported_response_type&error_description=Only+code+response_type+is+supported&state={state}");
    }

    // Validate code challenge method
    if (code_challenge_method != "S256")
    {
        return Results.Redirect($"{redirect_uri}?error=invalid_request&error_description=Only+S256+code_challenge_method+is+supported&state={state}");
    }

    // Validate resource in accordance with RFC 8707
    // if (string.IsNullOrEmpty(resource) || !ValidResources.Contains(resource))
    // {
    //     return Results.Redirect($"{redirect_uri}?error=invalid_target&error_description=The+specified+resource+is+not+valid&state={state}");
    // }

    // Generate a new authorization code
    var mcpAuthCode = HelperMethods.GenerateRandomToken();
    var requestedScopes = scope?.Split(' ').ToList() ?? [];
    var spotifyVerifier = HelperMethods.GenerateCodeVerifier();
    var spotifyChallenge = HelperMethods.ComputeCodeChallengeS256(spotifyVerifier);
    var spotifyServerState = HelperMethods.generateRandomString(32);

    // Redirect back to client with the code
    var redirectUrl = $"{redirect_uri}?code={mcpAuthCode}";
    if (!string.IsNullOrEmpty(state))
    {
        redirectUrl += $"&state={Uri.EscapeDataString(state)}";
    }

    if (!request.Host.ToString().Contains("localhost") && !request.Host.ToString().Contains("127.0.0.1"))
    {
        spotifyRedirectUri = $"https://{request.Host}/spotify-callback";
    }

    // Store code information for later verification
    _authCodes[mcpAuthCode] = new AuthorizationCodeInfo
    {
        ClientId = client_id,
        ClientRedirectUri = redirectUrl,
        CodeChallenge = code_challenge,
        Scope = requestedScopes,
        Resource = !string.IsNullOrEmpty(resource) ? new Uri(resource) : null,
        SpotifyCodeVerifier = spotifyVerifier,
        ClientState = state ?? string.Empty,
        SpotifyState = spotifyServerState,
        SpofityRedirectUri = spotifyRedirectUri
    };

    var spotifyRedirect = $"{spotifyAuthUrl}?response_type=code&client_id={spotifyClientId}&scope={Uri.EscapeDataString(spotifyScopes)}&redirect_uri={Uri.EscapeDataString(spotifyRedirectUri)}&code_challenge_method=S256&code_challenge={spotifyChallenge}&state={spotifyServerState}";

    app.Logger.LogInformation("Redirecting to Spotify: {spotifyRedirect}", spotifyRedirect);

    _mcpCodeMap[spotifyServerState] = mcpAuthCode;

    return Results.Redirect(spotifyRedirect); // redirect to spotify, then redirect back to initial URL???
});

app.MapGet("/spotify-callback", async (
    [FromQuery] string code,
    [FromQuery] string state
) =>
{
    var mcpCode = _mcpCodeMap[state];
    AuthorizationCodeInfo authCodeInfo = _authCodes[mcpCode];
    authCodeInfo.SpotifyAuthCode = code; // update the auth code info with the spotify code
    

    var clientRedirectUri = authCodeInfo.ClientRedirectUri;

    SpotifyTokenRequest tokenRequest = new SpotifyTokenRequest
    {
        GrantType = "authorization_code",
        Code = code,
        RedirectUri = authCodeInfo.SpofityRedirectUri,
        ClientId = spotifyClientId,
        CodeVerifier = authCodeInfo.SpotifyCodeVerifier
    };
    var httpService = app.Services.GetRequiredService<HttpService>();

    var spotifyTokenResponse = await httpService.GetSpotifyAccessToken(tokenRequest);
    authCodeInfo.SpotifyTokenResponse = spotifyTokenResponse;
    _authCodes[mcpCode] = authCodeInfo;

    app.Logger.LogInformation("Received Spotify token response: {spotifyTokenResponse}", spotifyTokenResponse.ToString());

    app.Logger.LogInformation("Authorization code info: {authCodeInfo}", authCodeInfo.ToString());

    // return to client with MCP Server auth code 
    return Results.Redirect(clientRedirectUri);
});

// Testing endpoint for scripting client redirect on /authorize
app.MapGet("/dummyRedirect", (
    [FromQuery] string code,
    [FromQuery] string? state
) =>
{
    var authCodeInfo = _authCodes[code];
    
    return Results.Ok($"Test successfull with auth code info: {authCodeInfo}");
});

// JWKS endpoint to expose the public key
app.MapGet("/.well-known/jwks.json", () =>
{
    var parameters = _rsa.ExportParameters(false);

    // Convert parameters to base64url encoding
    var e = WebEncoders.Base64UrlEncode(parameters.Exponent ?? Array.Empty<byte>());
    var n = WebEncoders.Base64UrlEncode(parameters.Modulus ?? Array.Empty<byte>());

    var jwks = new JsonWebKeySet
    {
        Keys = [
            new JsonWebKey
            {
                KeyType = "RSA",
                Use = "sig",
                KeyId = _keyID,
                Algorithm = "RS256",
                Exponent = e,
                Modulus = n
            }
        ]
    };

    return Results.Ok(jwks);
});

app.MapGet("/probe", () => Results.Ok("Server is running"));

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.Run();
