

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

                using StringContent content = new(
                    System.Text.Json.JsonSerializer.Serialize(requestBody),
                    System.Text.Encoding.UTF8,
                    "application/json");

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