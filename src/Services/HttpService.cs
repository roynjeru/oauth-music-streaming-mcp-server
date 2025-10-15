

using System.Text;
using System.Text.Json;
using src.Models;

namespace src.Services
{
    public class HttpService(IHttpClientFactory httpClientFactory, ILogger<HttpService> logger)
    {
        private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;
        private readonly ILogger<HttpService> _logger = logger;

        public async Task<SpotifyTokenResponse> GetSpotifyAccessToken(SpotifyTokenRequest requestBody)
        {
            var client = _httpClientFactory.CreateClient();

                KeyValuePair<string, string>[] kvp =
                [
                    new KeyValuePair<string, string>("grant_type", requestBody.GrantType),
                    new KeyValuePair<string, string>("code", requestBody.Code),
                    new KeyValuePair<string, string>("redirect_uri", requestBody.RedirectUri),
                    new KeyValuePair<string, string>("client_id", requestBody.ClientId),
                    new KeyValuePair<string, string>("code_verifier", requestBody.CodeVerifier)
                ];
                var content = new FormUrlEncodedContent(kvp);

                _logger.LogInformation($"Calling spotify token endpoint with body: {kvp}");

            // single retry for transient failures
            for (int attempt = 1; attempt <= 2; attempt++)
            {
                using HttpResponseMessage httpResponse = await client.PostAsync("https://accounts.spotify.com/api/token", content);

                if (httpResponse.IsSuccessStatusCode)
                {
                    SpotifyTokenResponse? responseContent = await httpResponse.Content.ReadFromJsonAsync<SpotifyTokenResponse>();
                    if (responseContent is null)
                    {
                        throw new InvalidOperationException("Spotify token endpoint returned an empty body");
                    }
                    responseContent.SetExpiry();
                    return responseContent;
                }

                var body = await httpResponse.Content.ReadAsStringAsync();
                _logger.LogWarning("Spotify token endpoint returned non-success (status={status}). Body: {body}", (int)httpResponse.StatusCode, body);

                // retry on 429 or 5xx
                if (attempt == 1 && ((int)httpResponse.StatusCode == 429 || (int)httpResponse.StatusCode >= 500))
                {
                    await Task.Delay(500);
                    continue;
                }

                throw new src.Models.SpotifyApiException((int)httpResponse.StatusCode, body);
            }

            throw new InvalidOperationException("Unreachable: GetSpotifyAccessToken finished retry loop without result");
        }

        /// <summary>
        /// Refreshes a Spotify access token using a refresh token.
        /// </summary>
        public async Task<SpotifyTokenResponse> RefreshSpotifyAccessToken(string refreshToken, string clientId)
        {
            try
            {
                var client = _httpClientFactory.CreateClient();

                var kvp = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("grant_type", "refresh_token"),
                    new KeyValuePair<string, string>("refresh_token", refreshToken),
                    new KeyValuePair<string, string>("client_id", clientId)
                };

                var content = new FormUrlEncodedContent(kvp);

                _logger.LogInformation("Refreshing Spotify access token for client {clientId}", clientId);
                // Execute request
                using HttpResponseMessage httpResponse = await client.PostAsync("https://accounts.spotify.com/api/token", content);

                if (httpResponse.IsSuccessStatusCode)
                {
                    SpotifyTokenResponse? responseContent = await httpResponse.Content.ReadFromJsonAsync<SpotifyTokenResponse>();
                    if (responseContent is null)
                    {
                        throw new InvalidOperationException("Spotify token endpoint returned an empty body");
                    }
                    responseContent.SetExpiry();
                    responseContent.RefreshToken = string.IsNullOrEmpty(responseContent.RefreshToken) ? refreshToken : responseContent.RefreshToken; // Spotify may not return a new refresh token, so keep using the old one if not provided

                    return responseContent;
                }

                var body = await httpResponse.Content.ReadAsStringAsync();
                _logger.LogWarning("Spotify refresh endpoint returned non-success (status={status}). Body: {body}", (int)httpResponse.StatusCode, body);

                // Retry once on transient failures
                if ((int)httpResponse.StatusCode == 429 || (int)httpResponse.StatusCode >= 500)
                {
                    await Task.Delay(500);
                    using HttpResponseMessage retryResponse = await client.PostAsync("https://accounts.spotify.com/api/token", content);
                    if (retryResponse.IsSuccessStatusCode)
                    {
                        SpotifyTokenResponse? responseContent = await retryResponse.Content.ReadFromJsonAsync<SpotifyTokenResponse>();
                        if (responseContent is null)
                        {
                            throw new InvalidOperationException("Spotify token endpoint returned an empty body on retry");
                        }
                        responseContent.SetExpiry();
                        responseContent.RefreshToken = string.IsNullOrEmpty(responseContent.RefreshToken) ? refreshToken : responseContent.RefreshToken;
                        return responseContent;
                    }

                    var retryBody = await retryResponse.Content.ReadAsStringAsync();
                    _logger.LogWarning("Spotify refresh retry returned non-success (status={status}). Body: {body}", (int)retryResponse.StatusCode, retryBody);
                    throw new src.Models.SpotifyApiException((int)retryResponse.StatusCode, retryBody);
                }

                throw new src.Models.SpotifyApiException((int)httpResponse.StatusCode, body);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error refreshing Spotify access token: {ex.Message}");
                throw;
            }
        }
    }
}