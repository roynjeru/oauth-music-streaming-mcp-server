

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
            try
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

                using HttpResponseMessage httpResponse = await client.PostAsync("https://accounts.spotify.com/api/token", content);

                httpResponse.EnsureSuccessStatusCode();
                SpotifyTokenResponse? responseContent = await httpResponse.Content.ReadFromJsonAsync<SpotifyTokenResponse>();
                if (responseContent is null)
                {
                    throw new InvalidOperationException("Spotify token endpoint returned an empty body");
                }
                responseContent.SetExpiry();

                return responseContent;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting Spotify access token: {ex.Message}");
                throw;
            }
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
                HttpResponseMessage httpResponse;
                try
                {
                    httpResponse = await client.PostAsync("https://accounts.spotify.com/api/token", content);

                    httpResponse.EnsureSuccessStatusCode();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, $"Error calling Spotify token endpoint: {ex.Message}");
                    throw; // Rethrow to surface the error to the calling function
                }
                
                SpotifyTokenResponse? responseContent = await httpResponse.Content.ReadFromJsonAsync<SpotifyTokenResponse>();
                if (responseContent is null)
                {
                    throw new InvalidOperationException("Spotify token endpoint returned an empty body");
                }
                responseContent.SetExpiry();
                responseContent.RefreshToken = string.IsNullOrEmpty(responseContent.RefreshToken) ? refreshToken : responseContent.RefreshToken; // Spotify may not return a new refresh token, so keep using the old one if not provided

                return responseContent;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error refreshing Spotify access token: {ex.Message}");
                throw;
            }
        }
    }
}