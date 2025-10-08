

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
                SpotifyTokenResponse responseContent = await httpResponse.Content.ReadFromJsonAsync<SpotifyTokenResponse>();

                return responseContent;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting Spotify access token: {ex.Message}");
                throw;
            }
        }
    }
}