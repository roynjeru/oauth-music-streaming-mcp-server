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
using System.Net.Http.Headers;

var builder = WebApplication.CreateBuilder(args);

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
ConcurrentDictionary<string, TokenRefreshInfo> _refreshTokens = new();
ConcurrentDictionary<string, SpotifyTokenResponse> _mcpToSpotify = new();

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

    app.Logger.LogInformation("RegisterRequest body from client: {regReqBody}", regReqBody.ToString());

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

    var registrationAccessToken = HelperMethods.generateRandomString(40);
    var issuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    var registrationClientUri = $"https://{request.Host}/register/{clientId}";

    var registered = new RegisteredClient
    {
        ClientId = clientId,
        RedirectUris = regReqBody.redirect_uris,
        ClientName = regReqBody.client_name,
        TokenEndpointAuthMethod = "none",
        GrantTypes = regReqBody.grant_types ?? new string[] { "authorization_code" },
        ResponseTypes = regReqBody.response_types ?? new string[] { "code" },
        Scope = regReqBody.scope + "openid profile email mcp:tools",
        RegistrationAccessToken = registrationAccessToken,
        ClientIdIssuedAt = issuedAt,
        RegistrationClientUri = registrationClientUri
    };

    _registeredClients[clientId] = registered;

    var resp = new RegisterResponse
    {
        client_id = registered.ClientId,
        client_id_issued_at = registered.ClientIdIssuedAt,
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
        client_id_issued_at = client.ClientIdIssuedAt,
        redirect_uris = client.RedirectUris,
        grant_types = client.GrantTypes,
        registration_client_uri = client.RegistrationClientUri,
        registration_access_token = client.RegistrationAccessToken,
        token_endpoint_auth_method = client.TokenEndpointAuthMethod,
        response_types = client.ResponseTypes,
        scope = client.Scope
    };
    
    return Results.Ok(client);
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
    if (!_registeredClients.TryGetValue(client_id, out var client))
    {
        return Results.BadRequest(new OAuthErrorResponse
        {
            Error = "invalid_client",
            ErrorDescription = "Client not found"
        });
    }

    // Validate redirect_uri
    if (string.IsNullOrEmpty(redirect_uri))
    {
        if (client.RedirectUris.Length == 1)
        {
            redirect_uri = client.RedirectUris[0];
        }
        else
        {
            return Results.BadRequest(new OAuthErrorResponse
            {
                Error = "invalid_request",
                ErrorDescription = "redirect_uri is required when client has multiple registered URIs"
            });
        }
    }
    else if (!client.RedirectUris.Contains(redirect_uri))
    {
        return Results.BadRequest(new OAuthErrorResponse
        {
            Error = "invalid_request",
            ErrorDescription = "Unregistered redirect_uri"
        });
    }

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
    if (string.IsNullOrEmpty(state))
    {
        state = HelperMethods.generateRandomString(32);
    }
    redirectUrl += $"&state={Uri.EscapeDataString(state)}";


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
app.MapPost("/token", ([FromForm] TokenRequest requestBody, RsaJwtIssuer issuerSvc, HttpContext context) =>
{
    app.Logger.LogInformation("token requestBody: {requestBody}", requestBody.ToString());

    if (requestBody == null || requestBody?.grant_type is null)
    {
        return Results.Json(new { error = "invalid_request", error_description = "grant_type is required" },
            statusCode: 400, contentType: "application/json");
    }

    if (requestBody.grant_type == "authorization_code")
    {
        // validate the mcpAuthCode from request exits in the store
        if (string.IsNullOrEmpty(requestBody.code) || !_authCodes.TryGetValue(requestBody.code, out var authCodeInfo))
        {
            return Results.Json(new
            {
                error = "invalid_grant",
                error_description = "Authorization code is invalid or has expired"
            }, statusCode: 400, contentType: "application/json");
        }

        // validate the client_id exists
        var clientId = authCodeInfo.ClientId;
        var client = _registeredClients[clientId];

        // validate redirect_uri (if provided in token request)
        if (!string.IsNullOrEmpty(requestBody.redirect_uri))
        {
            // Stored ClientRedirectUri was saved with query params (code & state). Strip query portion when comparing.
            var expectedRedirect = authCodeInfo.ClientRedirectUri ?? string.Empty;
            var qIdx = expectedRedirect.IndexOf('?');
            if (qIdx >= 0)
            {
                expectedRedirect = expectedRedirect.Substring(0, qIdx);
            }

            if (!string.Equals(requestBody.redirect_uri, expectedRedirect, StringComparison.OrdinalIgnoreCase))
            {
                return Results.Json(new
                {
                    error = "invalid_request",
                    error_description = "redirect_uri does not match the one used in the authorization request"
                }, statusCode: 400, contentType: "application/json");
            }
        }

        // validate PKCE: code_verifier must be present and must match the stored code_challenge
        if (string.IsNullOrEmpty(requestBody.code_verifier))
        {
            return Results.Json(new
            {
                error = "invalid_request",
                error_description = "code_verifier is required"
            }, statusCode: 400, contentType: "application/json");
        }

        // The authorization request enforces S256, so verify using the stored challenge.
        var pkceOk = HelperMethods.VerifyPkce(requestBody.code_verifier, authCodeInfo.CodeChallenge, null);
        if (!pkceOk)
        {
            app.Logger.LogWarning("PKCE verification failed for auth code {code}", requestBody.code);
            return Results.Json(new
            {
                error = "invalid_grant",
                error_description = "PKCE verification failed"
            }, statusCode: 400, contentType: "application/json");
        }
        app.Logger.LogInformation("PKCE verification succeeded for auth code {code}", requestBody.code);


        // One-time use: remove the authorization code so it cannot be replayed
        _authCodes.TryRemove(requestBody.code, out _);

        // [TODO] 
        // Generates encrypted session key for MCP API access
        // Caches the access token with session key mapping
        // Returns encrypted session key to MCP client

        // mint token 
        // [TODO]: add additional claims and expiration/lifetime based on spotify token info
        var jwt = issuerSvc.Mint("user1", lifetime: TimeSpan.FromMinutes(15));

        if (authCodeInfo?.SpotifyTokenResponse is not null)
        {
            _mcpToSpotify[jwt] = authCodeInfo.SpotifyTokenResponse;
        }

        // create a long-lived refresh token and store it with the client id
        var refreshToken = HelperMethods.GenerateRandomToken();
        _refreshTokens[refreshToken] = new TokenRefreshInfo
        {
            ClientId = clientId,
            Subject = "user1",
            Scope = client.Scope,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(30)
        };

        var resp = new TokenResponse
        {
            AccessToken = jwt,
            TokenType = "Bearer",
            ExpiresIn = 900, // 15 minutes
            RefreshToken = refreshToken,
            Scope = client.Scope
        };

        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-cache";
        return Results.Json(resp, statusCode: 200, contentType: "application/json");
    }
    else if (requestBody.grant_type == "refresh_token")
    {
        app.Logger.LogInformation("Refresh token requestBody: {requestBody}", requestBody.ToString());
        // 1) Basic validation
        if (string.IsNullOrEmpty(requestBody.refresh_token))
        {
            return Results.Json(new { error = "invalid_request", error_description = "refresh_token is required" },
                statusCode: 400, contentType: "application/json");
        }

        if (!_refreshTokens.TryGetValue(requestBody.refresh_token, out var refreshTokenInfo))
        {
            return Results.Json(new { error = "invalid_grant", error_description = "Unknown refresh_token" },
                statusCode: 400, contentType: "application/json");
        }

        // 2) Check expiry / revocation
        if (refreshTokenInfo.Revoked || refreshTokenInfo.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            return Results.Json(new { error = "invalid_grant", error_description = "Refresh token is expired or revoked" },
                statusCode: 400, contentType: "application/json");
        }

        // 3) validate Bind to client
        if (string.IsNullOrEmpty(requestBody.client_id) ||
            !_registeredClients.TryGetValue(requestBody.client_id, out var client) ||
            client.ClientId != refreshTokenInfo.ClientId)
        {
            return Results.Json(new { error = "invalid_client", error_description = "client_id mismatch for refresh_token" },
                statusCode: 401, contentType: "application/json");
        }

        // 4) Scope handling (requested scope must be equal or subset)
        var originalScope = refreshTokenInfo.Scope;
        var requestedScope = string.IsNullOrWhiteSpace(requestBody.scope) ? originalScope : requestBody.scope;
        if (!HelperMethods.IsScopeSubset(requestedScope, originalScope))
        {
            return Results.Json(new { error = "invalid_scope", error_description = "Requested scope exceeds original grant" },
                statusCode: 400, contentType: "application/json");
        }

        // 5) Mint new short-lived access token
        var newAccess = issuerSvc.Mint(refreshTokenInfo.Subject);

        // 6) Rotation (recommended): revoke old, issue new refresh
        refreshTokenInfo.Revoked = true;
        _refreshTokens[requestBody.refresh_token] = refreshTokenInfo;
        var newRefresh = HelperMethods.GenerateRandomToken();
        _refreshTokens[newRefresh] = new TokenRefreshInfo()
        {
            ClientId = refreshTokenInfo.ClientId,
            Subject = refreshTokenInfo.Subject,
            Scope = requestedScope,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(30),
            Parent = requestBody.refresh_token
        };

        var resp = new TokenResponse
        {
            AccessToken = newAccess,
            TokenType = "Bearer",
            ExpiresIn = 900,
            RefreshToken = newRefresh,
            Scope = requestedScope
        };

        app.Logger.LogInformation("Issued new access token and refresh token for client {clientId}", client.ClientId);

        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-cache";
        return Results.Json(resp, statusCode: 200, contentType: "application/json");
    }
    else
    {
        return Results.Json(new
        {
            error = "unsupported_grant_type",
            error_description = "Only authorization_code and refresh_token are supported"
        }, statusCode: 400, contentType: "application/json");
    }

})
.DisableAntiforgery();

app.MapPost("/exchange/spotify-token", async (HttpRequest request,
    IHttpClientFactory httpFactory,
    KeyMaterial keyMaterial
) =>
{
    // 1) Extract & validate our Bearer (the MCP access token we minted)
    var authHeader = request.Headers.Authorization.ToString();
    if (string.IsNullOrWhiteSpace(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
    {
        return Results.Json(new { error = "invalid_request", error_description = "Missing or invalid Authorization header" }, statusCode: 401);
    }

    var bearer = authHeader.Substring("Bearer ".Length).Trim();

    // Build token validation parameters using the same issuer/audience/key you mint with
    var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
    var validationParams = new TokenValidationParameters
    {
        ValidateAudience = true,
        ValidateIssuer = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidAudience = "my-mcp-server",
        ValidIssuer = env_issuer,
        ClockSkew = TimeSpan.FromSeconds(30),
        // Provide the signing key so the validator can verify signatures.
        IssuerSigningKey = new RsaSecurityKey(keyMaterial.Rsa) { KeyId = keyMaterial.Kid }
    };

    try
    {
        tokenHandler.ValidateToken(bearer, validationParams, out var _);
    }
    catch (Exception ex)
    {
        return Results.Json(new { error = "invalid_token", error_description = $"Access token validation failed: {ex.Message}" }, statusCode: 401);
    }

    app.Logger.LogInformation("/exchange/spotify-token Validated MCP access token");

    // 2) Look up the Spotify token response bound to this MCP access token
    if (!_mcpToSpotify.TryGetValue(bearer, out var spotifyTokenResponse) || spotifyTokenResponse is null)
    {
        return Results.Json(new { error = "not_found", error_description = "No Spotify token found for this access token" }, statusCode: 404);
    }

    // 3) If Spotify access token is expired, refresh it
    var now = DateTimeOffset.UtcNow;

    if (spotifyTokenResponse.GetExpiry() <= now.AddSeconds(30))
    {
        var httpService = app.Services.GetRequiredService<HttpService>();
        try
        {
            var requestResponse = await httpService.RefreshSpotifyAccessToken(spotifyTokenResponse.RefreshToken ?? string.Empty, spotifyClientId);
            spotifyTokenResponse = requestResponse;
            _mcpToSpotify[bearer] = spotifyTokenResponse; // update mapping
        }
        catch (src.Models.SpotifyApiException ex)
        {
            app.Logger.LogError(ex, "Spotify refresh failed: {status} {body}", ex.StatusCode, ex.ResponseBody);
            return Results.Json(new { error = "upstream_error", error_description = "Failed to refresh Spotify token" }, statusCode: 502);
        }
    }

    // 4) Return the Spotify access token payload
    return Results.Json(new
    {
        access_token = spotifyTokenResponse.AccessToken,
        token_type = "Bearer",
        expires_in = spotifyTokenResponse.ExpiresIn,
        scope = spotifyTokenResponse.Scope,
        refresh_token = spotifyTokenResponse.RefreshToken
    }, statusCode: 200, contentType: "application/json");
})
.DisableAntiforgery();


app.MapPost("/revoke", ([FromForm] string token, [FromForm] string? token_type_hint) =>
{
    if (string.IsNullOrWhiteSpace(token))
    {
        return Results.BadRequest(new { error = "invalid_request", error_description = "token is required" });
    }

    if (_refreshTokens.TryGetValue(token, out var rt))
    {
        rt.Revoked = true;
        _refreshTokens[token] = rt;
    }
    // Per RFC 7009, return 200 even if token is unknown
    return Results.Ok();
})
.DisableAntiforgery();


// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.Run();
