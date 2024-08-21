using BenchmarkDotNet.Running;
using JWT;

var jwt = new JWTTest();
jwt.Setup();
//var value = jwt.EncryptSymetric();
//Console.WriteLine(Convert.ToBase64String(value));
//var msg = jwt.DecryptSymetric();
//Console.WriteLine(msg);


//value = jwt.EncryptAsymetric();
//Console.WriteLine(Convert.ToBase64String(value));
//msg = jwt.DecryptAsymetric();
//Console.WriteLine(msg);
var token = jwt.GenerateJWT();
Console.WriteLine(token);
Console.WriteLine(jwt.ValidateJWT(token));

//var summary = BenchmarkRunner.Run<JWTTest>();