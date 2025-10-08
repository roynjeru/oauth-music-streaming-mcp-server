using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace src.Helpers
{
    public static class HelperMethods
    {
        /// <summary>
        /// Generates a random token for authorization code or refresh token.
        /// </summary>
        /// <returns>A Base64Url encoded random token.</returns>
        public static string GenerateRandomToken()
        {
            var bytes = new byte[32];
            Random.Shared.NextBytes(bytes);
            return WebEncoders.Base64UrlEncode(bytes);
        }

        public static string generateRandomString(int length)
        {
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var stringChars = new char[length];
            var random = new Random();

            for (int i = 0; i < stringChars.Length; i++)
            {
                stringChars[i] = chars[random.Next(chars.Length)];
            }

            return string.Join("", stringChars);
        }

        public static bool IsValidRedirectUri(string uri)
        {
            if (string.IsNullOrEmpty(uri)) return false;
            if (!Uri.TryCreate(uri, UriKind.Absolute, out var u)) return false;

            // Per RFC and MCP: allow localhost loopback and https schemes
            if (u.Scheme == Uri.UriSchemeHttps) return true;
            if ((u.Scheme == Uri.UriSchemeHttp) && (u.Host == "localhost" || u.Host == "127.0.0.1")) return true;
            return false;
        }

        public static string GenerateCodeVerifier()
        {
            // RFC 7636 recommends code verifier between 43 and 128 characters
            var rng = RandomNumberGenerator.Create();
            var bytes = new byte[64];
            rng.GetBytes(bytes);
            return Base64UrlEncode(bytes);
        }

        public static string ComputeCodeChallengeS256(string verifier)
        {
            using var sha = SHA256.Create();
            var hash = sha.ComputeHash(Encoding.ASCII.GetBytes(verifier));
            return Base64UrlEncode(hash);
        }

        public static bool VerifyPkce(string? verifier, string? challenge, string? method)
        {
            if (string.IsNullOrEmpty(challenge)) return false;
            if (string.IsNullOrEmpty(verifier)) return false;

            var m = (method ?? "S256").ToUpperInvariant();
            if (m == "PLAIN")
            {
                return verifier == challenge;
            }

            // Default to S256
            using var sha = SHA256.Create();
            var hash = sha.ComputeHash(Encoding.ASCII.GetBytes(verifier));
            var b64 = Base64UrlEncode(hash);
            return string.Equals(b64, challenge, StringComparison.OrdinalIgnoreCase);
        }

        public static string Base64UrlEncode(byte[] input)
        {
            var s = Convert.ToBase64String(input);
            s = s.TrimEnd('=');
            s = s.Replace('+', '-').Replace('/', '_');
            return s;
        }
    }
}

