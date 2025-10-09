using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace src.Singletons
{
    public sealed class RsaJwtIssuer
    {
        private readonly string _issuer;
        private readonly string _audience;
        private readonly SigningCredentials _creds;
        private readonly string _kid;

        public RsaJwtIssuer(string issuer, string audience, KeyMaterial keyMaterial)
        {
            _issuer = issuer;
            _audience = audience;
            _creds = keyMaterial.SigningCredentials;
            _kid = keyMaterial.Kid;
        }

        public string Mint(string subject, IEnumerable<Claim>? additionalClaims = null, TimeSpan? lifetime = null)
        {
            var now = DateTimeOffset.UtcNow;
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, subject),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
                new Claim(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString()), // (Issued At) Claim
            };
            if (additionalClaims != null)
            {
                claims.AddRange(additionalClaims);
            }

            var handler = new JwtSecurityTokenHandler();
            var token = handler.CreateJwtSecurityToken(new SecurityTokenDescriptor
            {
                Issuer = _issuer,
                Audience = _audience,
                Subject = new ClaimsIdentity(claims),
                NotBefore = now.UtcDateTime,
                Expires = (now + (lifetime ?? TimeSpan.FromMinutes(15))).UtcDateTime,
                SigningCredentials = _creds,
                AdditionalHeaderClaims = new Dictionary<string, object> { { "kid", _kid } }
            });

            return handler.WriteToken(token);
        }
    }
}