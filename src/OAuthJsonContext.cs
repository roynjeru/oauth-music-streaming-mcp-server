using System.Text.Json.Serialization;

namespace OAuthServer;

[JsonSerializable(typeof(OAuthServerMetadata))]
[JsonSerializable(typeof(AuthorizationServerMetadata))]
[JsonSerializable(typeof(TokenResponse))]
[JsonSerializable(typeof(JsonWebKeySet))]
[JsonSerializable(typeof(JsonWebKey))]
[JsonSerializable(typeof(TokenIntrospectionResponse))]
[JsonSerializable(typeof(OAuthErrorResponse))]
[JsonSerializable(typeof(ClientRegistrationRequest))]
[JsonSerializable(typeof(ClientRegistrationResponse))]
[JsonSerializable(typeof(Dictionary<string, string>))]
internal sealed partial class OAuthJsonContext : JsonSerializerContext;
