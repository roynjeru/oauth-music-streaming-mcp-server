
namespace src.Models
{
    public class TokenRefreshInfo
    {
        public required string ClientId { get; set; }
        public required string Subject { get; set; }
        public required string Scope { get; set; }
        public DateTimeOffset ExpiresAt { get; set; }
        public bool Revoked = false;
        public string? Parent { get; set; } = null;
    }
}