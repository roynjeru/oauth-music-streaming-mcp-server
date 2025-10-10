using Azure.Monitor.OpenTelemetry.AspNetCore;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using src.Helpers;
using src.Models;
using src.Services;
using src.Singletons;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);

// get URL and port from environment variable if set
int port = int.Parse(Environment.GetEnvironmentVariable("WEBSITE_PORT"));

var spotifyAuthUrl = "https://accounts.spotify.com/authorize";
var spotifyScopes = "user-read-private user-read-email streaming user-read-playback-state user-modify-playback-state";
var spotifyClientId = "04e740f554cc46469e3645a37b861a75";
var spotifyRedirectUri = "http://127.0.0.1:8080/spotify-callback";

var kid = builder.Configuration["jwt-kid"];
var pemPrivateKey = builder.Configuration["jwt-pemPrivateKey"];

var env_issuer = builder.Configuration["env-issuer"];
var audience = "my-mcp-server";

var keys = new KeyMaterial(pemPrivateKey, kid);
var issuerService = new RsaJwtIssuer(env_issuer, audience, keys);

builder.Services.AddSingleton(keys);
builder.Services.AddSingleton(issuerService);


// Port 5000 is used by tests and port 7071 is used by the ProtectedMcpServer sample
// string[] ValidResources = ["http://localhost:5000/", "http://localhost:7071/"];

ConcurrentDictionary<string, AuthorizationCodeInfo> _authCodes = new();
ConcurrentDictionary<string, string> _mcpCodeMap = new();
ConcurrentDictionary<string, TokenInfo> _tokens = new();
ConcurrentDictionary<string, RegisteredClient> _registeredClients = new();

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
builder.Services.AddAntiforgery();

var app = builder.Build();

app.UseRouting();
app.UseAntiforgery();
app.UseEndpoints(_ => { });

// OAuth 2.0 Authorization Server Metadata (RFC 8414)
app.MapGet("/.well-known/oauth-authorization-server", (HttpContext context, HttpRequest request) =>
{
    var requestScheme = "https";
    string requestUrl = $"{requestScheme}://{request.Host}";
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
        TokenEndpointAuthMethodsSupported = ["none"], // no cient auth, require code_verifier
        ClaimsSupported = ["sub", "iss", "name", "email", "aud"],
        CodeChallengeMethodsSupported = ["S256"],
        GrantTypesSupported = ["authorization_code", "refresh_token"],
        RegistrationEndpoint = $"{requestUrl}/register"
    };

    return Results.Ok(metadata);
});

// JWKS endpoint to expose the public key
app.MapGet("/.well-known/jwks.json", () =>
{
    var jwks = keys.Jwks; // contains: kty=RSA, use=sig, kid, alg=RS256, n, e
    var response = new
    {
        keys = jwks.Keys.Select(k => new
        {
            kty = k.Kty,
            use = k.Use,
            kid = k.Kid,
            alg = k.Alg,
            n = k.N,
            e = k.E
        })
    };

    // Cache for a short period to let validators refresh
    return Results.Json(response,
        statusCode: 200,
        contentType: "application/json");
});

// ---- OIDC Discovery (OpenID Provider Metadata) ----
app.MapGet("/.well-known/openid-configuration", (HttpContext http) =>
{
    var doc = new OpenIdDiscovery
    {
        issuer = env_issuer,
        jwks_uri = $"{env_issuer}/.well-known/jwks.json", // TODO: from env
        authorization_endpoint = $"{env_issuer}/authorize", // TODO: from env
        token_endpoint = $"{env_issuer}/token", // TODO: from env
        response_types_supported = ["code"],
        response_modes_supported = ["query", "fragment", "form_post"],
        grant_types_supported = ["authorization_code", "refresh_token"],
        code_challenge_methods_supported = ["S256"],
        subject_types_supported = ["public"],
        id_token_signing_alg_values_supported = ["RS256"],
        token_endpoint_auth_methods_supported = ["none"], // no cient auth, require code_verifier
        scopes_supported = ["openid", "profile", "email", "mcp:tools"],
        claims_supported = ["sub", "iss", "name", "email", "aud"]
    };

    // Cache for a few minutes so clients can refresh keys/metadata
    http.Response.Headers.CacheControl = "public, max-age=300";

    return Results.Json(doc, new System.Text.Json.JsonSerializerOptions
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    });
});

app.MapPost("/register", ([FromBody] RegisterRequest? regReqBody, HttpRequest request) =>
{
    if (regReqBody == null)
    {
        return Results.Json(new
        {
            error = "invalid_client_metadata",
            error_description = "Request body is required"
        }, statusCode: 400, contentType: "application/json");
    }

    if (regReqBody.redirect_uris == null || regReqBody.redirect_uris.Length == 0)
    {
        return Results.Json(new
        {
            error = "invalid_redirect_uri",
            error_description = "At least one redirect_uri is required"
        }, statusCode: 400, contentType: "application/json");
    }

    foreach (var uri in regReqBody.redirect_uris)
    {
        if (!HelperMethods.IsValidRedirectUri(uri))
        {
            return Results.Json(new
            {
                error = "invalid_redirect_uri",
                error_description = $"The redirect_uri '{uri}' is not valid"
            }, statusCode: 400, contentType: "application/json");
        }
    }

    // Example: check for inconsistent grant_types/response_types
    if (regReqBody.grant_types != null && regReqBody.response_types != null)
    {
        // If response_types contains "code", grant_types must contain "authorization_code"
        if (regReqBody.response_types.Contains("code") && !regReqBody.grant_types.Contains("authorization_code"))
        {
            return Results.Json(new
            {
                error = "invalid_client_metadata",
                error_description = "The grant type 'authorization_code' must be registered along with the response type 'code'."
            }, statusCode: 400, contentType: "application/json");
        }
    }

    // determine client's requested auth method for token endpoint
    var clientAuthMethod = string.IsNullOrEmpty(regReqBody.token_endpoint_auth_method) ? "none" : regReqBody.token_endpoint_auth_method;

    var clientId = HelperMethods.generateRandomString(24);

    string? clientSecret = null;

    if (clientAuthMethod == "client_secret_basic" || clientAuthMethod == "client_secret_post")
    {
        clientSecret = HelperMethods.generateRandomString(40);
    }

    var registrationAccessToken = HelperMethods.generateRandomString(40);
    var issuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    var registrationClientUri = $"https://{request.Host}/register/{clientId}";

    var registered = new RegisteredClient
    {
        ClientId = clientId,
        ClientSecret = clientSecret,
        RedirectUris = regReqBody.redirect_uris,
        ClientName = regReqBody.client_name,
        TokenEndpointAuthMethod = clientAuthMethod,
        GrantTypes = regReqBody.grant_types ?? new string[] { "authorization_code" },
        ResponseTypes = regReqBody.response_types ?? new string[] { "code" },
        Scope = regReqBody.scope,
        RegistrationAccessToken = registrationAccessToken,
        ClientIdIssuedAt = issuedAt,
        RegistrationClientUri = registrationClientUri
    };

    _registeredClients[clientId] = registered;

    var resp = new RegisterResponse
    {
        client_id = registered.ClientId,
        client_secret = registered.ClientSecret,
        client_id_issued_at = registered.ClientIdIssuedAt,
        client_secret_expires_at = "0", // never expires
        redirect_uris = registered.RedirectUris,
        grant_types = registered.GrantTypes,
        registration_client_uri = registered.RegistrationClientUri,
        registration_access_token = registered.RegistrationAccessToken,
        token_endpoint_auth_method = registered.TokenEndpointAuthMethod,
        response_types = registered.ResponseTypes,
        scope = registered.Scope
    };

    return Results.Created(registered.RegistrationClientUri, resp);
});

app.MapGet("/register/{clientId}", (
    [FromRoute] string clientId, HttpRequest request) =>
{
    if (string.IsNullOrEmpty(clientId) || !_registeredClients.TryGetValue(clientId, out var client))
    {
        return Results.Json(new
        {
            error = "invalid_client",
            error_description = "Client not found"
        }, statusCode: 404, contentType: "application/json");
    }

    // Expect Authorization: Bearer <registration_access_token>
    var authHeader = request.Headers.Authorization.ToString();
    if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
    {
        return Results.Json(new
        {
            error = "invalid_request",
            error_description = "Missing or invalid Authorization header"
        }, statusCode: 401, contentType: "application/json");
    }

    string token = authHeader.ToString().StartsWith("Bearer ") ? authHeader.Substring("Bearer ".Length).Trim() : authHeader;

    if (token != client.RegistrationAccessToken)
    {
        return Results.Json(new
        {
            error = "invalid_token",
            error_description = "Invalid registration access token"
        }, statusCode: 401, contentType: "application/json");
    }

    var resp = new RegisterResponse
    {
        client_id = client.ClientId,
        client_secret = client.ClientSecret,
        client_id_issued_at = client.ClientIdIssuedAt,
        client_secret_expires_at = "0", // never expires
        redirect_uris = client.RedirectUris,
        grant_types = client.GrantTypes,
        registration_client_uri = client.RegistrationClientUri,
        registration_access_token = client.RegistrationAccessToken,
        token_endpoint_auth_method = client.TokenEndpointAuthMethod,
        response_types = client.ResponseTypes,
        scope = client.Scope
    };
    
    return Results.Ok(resp);
});

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
    // if (!_registeredClients.TryGetValue(client_id, out var client))
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

app.MapGet("/probe", () => Results.Ok("Server is running"));

// mint tokens
// Token endpoint for MCP clients to exchange an MCP code for an access token.
app.MapPost("/token", ([FromBody] TokenRequest requestBody, RsaJwtIssuer issuerSvc) =>
{
    if (requestBody == null || requestBody.grant_type != "authorization_code")
    {
        return Results.Json(new
        {
            error = "unsupported_grant_type",
            error_description = "Only authorization_code grant_type is supported"
        }, statusCode: 400, contentType: "application/json");
    }

    // validate the mcpAuthCode from request exits in the store
    if (string.IsNullOrEmpty(requestBody.code) || !_authCodes.TryGetValue(requestBody.code, out var authCodeInfo))
    {
        return Results.Json(new
        {
            error = "invalid_grant",
            error_description = "Authorization code is invalid or has expired"
        }, statusCode: 400, contentType: "application/json");
    }

    app.Logger.LogInformation("token requestBody: {requestBody}", requestBody.ToString());

    // validate redirect_uri

    // validate PKCE 

    // validate code_verifier and code_challenge

    // [TODO] 
    // Generates encrypted session key for MCP API access
    // Caches the access token with session key mapping
    // Returns encrypted session key to MCP client

    // mint token 
    // [TODO]: add additional claims and expiration/lifetime based on spotify token info
    var jwt = issuerSvc.Mint("user1");

    return Results.Ok(new { access_token = jwt, token_type = "Bearer", expires_in = 900 });
});

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.Run();
