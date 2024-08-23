using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.LoggingExtensions;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

namespace JWT
{
    public class openIdConnect(X509Certificate2 certificate, string issuer)
    {
        public async Task RunAsync()
        {
            #region Advance loging for microsoft.idenity.model lib
            using var loggerFactory = LoggerFactory.Create(loggingBuilder => loggingBuilder
                                .SetMinimumLevel(LogLevel.Trace)
                                .AddConsole());
            IdentityModelEventSource.ShowPII = true;
            LogHelper.Logger = new IdentityLoggerAdapter(loggerFactory.CreateLogger("MSAL"));
            LogHelper.IsEnabled(Microsoft.IdentityModel.Abstractions.EventLogLevel.Verbose);
            #endregion

            var builder = WebApplication.CreateBuilder();
            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, (opt) =>
                {
                    opt.Audience = "api://AzureADTokenExchange";
                    opt.Authority = issuer;
                    opt.RequireHttpsMetadata = true;
                });

            builder.Services.AddAuthorization();

            var app = builder.Build();
            app.UseAuthentication(); // adding JWT middleware
            app.UseRouting(); // routing middleware
            app.UseAuthorization(); // adding Authz middleware


            // Openid configurtaion endpoint
            app.Map(".well-known/openid-configuration", () => Results.Ok(new OpenidDocument(issuer)));
            // Keydiscover Endpoint
            app.Map("discovery/keys", () => Results.Ok(new { keys = GetKeys() }));
            // Token Endpoint
            app.Map("token", () => Results.Ok(new { token = GetToken() }));
            // Protected Data endpoint
            app.Map("api/data", () => Results.Ok("Protected Data")).RequireAuthorization();


            await app.RunAsync();
        }
        JsonWebKey[] GetKeys()
        {
            // get only public Part of cert
            var publicCert = new X509Certificate2(certificate.Export(X509ContentType.Cert));
            //Convert to Security Key
            var key = new X509SecurityKey(publicCert);
            // Convert to JWK key as RSA
            var jwk1 = JsonWebKeyConverter.ConvertFromX509SecurityKey(key, true);
            // set key use as sign since we use this for sigining
            jwk1.Use = "sig";
            // Also add x509 part to the jwk
            jwk1.X5t = key.X5t;
            jwk1.X5c.Add(Convert.ToBase64String(key.Certificate.RawData));
            return [jwk1];
        }
        string GetToken()
        {
            // Creating Claim List
            var claims = new List<Claim>
                {
                    new Claim("sub", "mytest"),
                };
            //Generating Security key from cert 
            var secretKey = new X509SecurityKey(certificate);
            //converting to Signing Creds and specify algo 
            var signinCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.RsaSha256);

            // cretaing the payload
            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: "api://AzureADTokenExchange", // aud for FIC
                claims: claims,
                expires: DateTime.Now.AddMinutes(50),
                notBefore: DateTime.Now.AddMinutes(-1),
                signingCredentials: signinCredentials
            );
            token.Payload.Add("iat", EpochTime.GetIntDate(DateTime.Now.ToUniversalTime()));
            return new JwtSecurityTokenHandler().WriteToken(token); //generate the token
        }
    }

    // Discovery Document
    class OpenidDocument(string issuer)
    {
        public string issuer { get; set; } = issuer;
        public string[] response_types_supported { get; set; } = ["token"];
        public string jwks_uri { get; set; } = $"{issuer}/discovery/keys";
        public string[] subject_types_supported { get; set; } = ["public"];
        public string[] id_token_signing_alg_values_supported { get; set; } = ["RS256"];
        public string authorization_endpoint { get; set; } = "https://unimplemented";
        public string token_endpoint { get; set; } = $"{issuer}/token";
    }
}
