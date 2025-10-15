using System;

namespace src.Models
{
    public sealed class SpotifyApiException : Exception
    {
        public int StatusCode { get; }
        public string? ResponseBody { get; }

        public SpotifyApiException(int statusCode, string? responseBody)
            : base($"Spotify API error: {statusCode} - {responseBody}")
        {
            StatusCode = statusCode;
            ResponseBody = responseBody;
        }
    }
}
