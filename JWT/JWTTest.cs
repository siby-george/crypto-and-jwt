using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace JWT
{
    [SimpleJob(RuntimeMoniker.Net80)]
    [MemoryDiagnoser]
    public class JWTTest
    {
        private SHA256 sha256 = SHA256.Create();
        private MD5 md5 = MD5.Create();
        private Aes aes = Aes.Create();
        public X509Certificate2 cert;


        private byte[] data = Encoding.ASCII.GetBytes("This is my message");
        private byte[] encDataAsymetric = Convert.FromBase64String("JBeUI9/WWFx01Z2NWPoBRGdduFbStuSnuZKOqgPCGqE6nhs1HouW1lSxVAGvLHvjBmGOJDzX9gmjioVpp6aXPLLy5enDV9gqNfGzpU5QhOKiD6ztkL11bNqD2ZiLMkku7qNgiXC3526VL1qnlRi1FKTl6UkWNwpetZDBOrGuR3dPSjPH4UwtUClx7kqnAvE3QnXvlNvEvboOpO9SOcRX2NlCrIQDgcOnzJJPlJflNgZVix0RBDdHbX9/PqdyOhVbZoD63YR/PaEPIH0IDxv8tS2PDWcDIj4O4gavrPT60+2dCdrUUPCoNyeSt+1Ohc97GB0WxIUuBiAaiPNIC7gBXA==");
        private byte[] encDataSymetric = Convert.FromBase64String("mwuPj2PyY97I6KRXRtgrOXe0S4fxHEW6V6nqLeK7hAE=");
        private byte[] CertBytes = Convert.FromBase64String("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");

        [GlobalSetup]
        public void Setup()
        {
            aes.IV = new byte[aes.BlockSize/8];
            aes.Key= SHA256.Create().ComputeHash(Encoding.ASCII.GetBytes("My Password"));
            //var rsa = RSA.Create();
            //var req = new CertificateRequest($"cn=MyCert", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            //cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));            
            cert = new X509Certificate2(CertBytes,"");

        }

        [Benchmark]
        public byte[] Sha256() => sha256.ComputeHash(data);

        [Benchmark]
        public byte[] Md5() => md5.ComputeHash(data);

        [Benchmark]
        public byte[] EncryptSymetric()
        {
            using var outStream = new MemoryStream();
            using var encryptor = new CryptoStream(outStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
            encryptor.Write(data);
            encryptor.FlushFinalBlock();
            return outStream.ToArray();
        }

        [Benchmark]
        public string DecryptSymetric()
        {
            using var outStream = new MemoryStream();
            using var decryptor = new CryptoStream(outStream, aes.CreateDecryptor(), CryptoStreamMode.Write);
            decryptor.Write(encDataSymetric);
            decryptor.FlushFinalBlock();
            return Encoding.ASCII.GetString(outStream.ToArray());
        }

        [Benchmark]
        public byte[] EncryptAsymetric()
        {
            return cert.GetRSAPublicKey()!.Encrypt(data, RSAEncryptionPadding.Pkcs1);
        }

        [Benchmark]
        public string DecryptAsymetric()
        {
            
            return Encoding.ASCII.GetString(cert.GetRSAPrivateKey()!.Decrypt(encDataAsymetric, RSAEncryptionPadding.Pkcs1));
        }

        public string GenerateJWT()
        {
            var claims = new List<Claim>
                {
                    new Claim("Name", "Siby"),
                };
            Console.WriteLine(Convert.ToBase64String(SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes("Our Secret"))));
            var secretKey = new SymmetricSecurityKey(SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes("Our Secret")));
            var signinCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);
            var tokeOptions = new JwtSecurityToken(
                issuer: "https://azureContainerRegistry.Azure.com",
                audience:"httpc://azurecr.io",
                claims: claims,
                expires: DateTime.Now.AddMinutes(50),
                signingCredentials: signinCredentials
            );
            return new JwtSecurityTokenHandler().WriteToken(tokeOptions);
        }

        public bool ValidateJWT(string jwt)
        {
            var secretKey = new SymmetricSecurityKey(SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes("Our Secret")));
            var result= new JwtSecurityTokenHandler().ValidateToken(jwt, new TokenValidationParameters() {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer= "https://azureContainerRegistry.Azure.com",
                ValidAudience= "httpc://azurecr.io",
                IssuerSigningKey = secretKey }, out var securityToken);
            return true;
        }
    }
}
