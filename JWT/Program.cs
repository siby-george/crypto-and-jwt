using JWT;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;



var jwt = new JWTTest();
jwt.Setup();

////var value = jwt.EncryptSymetric();
////Console.WriteLine(Convert.ToBase64String(value));
////var msg = jwt.DecryptSymetric();
////Console.WriteLine(msg);


////value = jwt.EncryptAsymetric();
////Console.WriteLine(Convert.ToBase64String(value));
////msg = jwt.DecryptAsymetric();
////Console.WriteLine(msg);
//var token = jwt.GenerateJWT();
//Console.WriteLine(token);
//Console.WriteLine(jwt.ValidateJWT(token));

////var summary = BenchmarkRunner.Run<JWTTest>();



const string issuer = "https://t0qlr94w-60626.usw2.devtunnels.ms";
var publicCert = new X509Certificate2(jwt.cert.Export(X509ContentType.Cert));
var key = new X509SecurityKey(publicCert);
var jwk1 = JsonWebKeyConverter.ConvertFromX509SecurityKey(key, true);
jwk1.X5t = key.X5t;
jwk1.Use = "sig";
jwk1.X5c.Add(Convert.ToBase64String(key.Certificate.RawData));
var JWKs = new JsonWebKey[] { jwk1 };
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.UseRouting();
app.Map(".well-known/openid-configuration", () => Results.Ok(new OpenidDocument(issuer)));
app.Map("discovery/keys", () => Results.Ok(new { keys = JWKs }));
app.Map("token", () => Results.Ok(new { token = GetToken(jwt.cert) }));
app.Run();
string GetToken(X509Certificate2 cert)
{
    var claims = new List<Claim>
                {
                    new Claim("sub", "mytest"),
                };
    var secretKey = new X509SecurityKey(jwt.cert);
    var signinCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.RsaSha256);
    var token = new JwtSecurityToken(
        issuer: issuer,
        audience: "api://AzureADTokenExchange",
        claims: claims,
       
        expires: DateTime.Now.AddMinutes(50),
        notBefore: DateTime.Now.AddMinutes(-1),
        signingCredentials: signinCredentials
    );
    token.Payload.Add("iat", EpochTime.GetIntDate(DateTime.Now.ToUniversalTime()));
    return new JwtSecurityTokenHandler().WriteToken(token);
}

class OpenidDocument(string issuer)
{
    public string issuer { get; set; }= issuer;
    public string jwks_uri { get; set; } = $"{issuer}/discovery/keys";
    public string[] response_types_supported { get; set; } = ["token"];
    public string[] subject_types_supported { get; set; } = ["public"];
    public string[] id_token_signing_alg_values_supported { get; set; } = ["RS256"];
    public string authorization_endpoint { get; set; } = "https://unimplemented";
    public string token_endpoint { get; set; } = $"{issuer}/token";
}