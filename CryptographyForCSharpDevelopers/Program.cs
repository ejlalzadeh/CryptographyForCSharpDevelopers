using System.Security.Cryptography;
using CryptographyForCSharpDevelopers.DigitalSign;
using CryptographyForCSharpDevelopers.Hashing;
using CryptographyForCSharpDevelopers.HMAC;

static void Print(string title, string data) => Console.WriteLine($"{title}\n{data}\n");
string dataToSign = "Cando";


//Digital Sign

//1
Print(nameof(RsaDigitalSign.Sign), RsaDigitalSign.Sign(dataToSign));

//2
string signPem = RsaDigitalSign.SignPem(dataToSign, File.ReadAllText("./Keys/privateKey.pem"));
Print(nameof(RsaDigitalSign.SignPem), signPem);

//3
string signFromEncryptedPem = RsaDigitalSign.SignWithEncryptedPem(dataToSign, File.ReadAllText("./Keys/encryptedPrivateKey.pem"), "P@ssw0rd");
Print(nameof(RsaDigitalSign.SignWithEncryptedPem), signFromEncryptedPem);

//Verification
Print(nameof(RsaDigitalSign.VerifyPem), RsaDigitalSign.VerifyPem(dataToSign, signPem, File.ReadAllText("./Keys/publicKey.pem")).ToString());

Print(nameof(RsaDigitalSign.VerifyPemPure), RsaDigitalSign.VerifyPemPure(dataToSign, signFromEncryptedPem, File.ReadAllText("./Keys/publicKey.pem")).ToString());


//Hmac
Print(nameof(Hmac.GenerateHmacSha256), Hmac.GenerateHmacSha256("Lhwed&lQpl", dataToSign));



//Hashing
Print(nameof(SHA256), Hashing.GenerateSha256HashString(dataToSign));