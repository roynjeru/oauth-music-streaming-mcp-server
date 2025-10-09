using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace src.Singletons
{
    public sealed class KeyMaterial
    {
        public RSA Rsa { get; }
        public string Kid { get; }
        public SigningCredentials SigningCredentials { get; }
        public JsonWebKeySet Jwks { get; }

        public KeyMaterial(string pemPrivateKey, string kid)
        {
            Kid = kid;

            // Load the RSA private key from PEM format
            Rsa = RSA.Create(); // Creates an instance of the default implementation of the RSA algorithm.
            Rsa.ImportFromPem(pemPrivateKey.AsSpan());

            var rsaKey = new RsaSecurityKey(Rsa) { KeyId = Kid };
            SigningCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256);

            // Build JWKS (public only)
            var parameters = Rsa.ExportParameters(false); // false to export public key only
            var n = Base64UrlEncoder.Encode(parameters.Modulus!);
            var e = Base64UrlEncoder.Encode(parameters.Exponent!);

            var jwk = new JsonWebKey
            {
                Kty = "RSA",
                Use = "sig",
                Kid = Kid,
                Alg = SecurityAlgorithms.RsaSha256,
                N = n,
                E = e
            };

            Jwks = new JsonWebKeySet();
            Jwks.Keys.Add(jwk);
        }
    }
}