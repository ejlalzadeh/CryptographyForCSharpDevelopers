using CryptographyForCSharpDevelopers.DigitalSign;
using CryptographyForCSharpDevelopers.HMAC;

string dataToSign = "Cando";





//Digital Sign
Print(nameof(RsaDigitalSign.Sign), RsaDigitalSign.Sign(dataToSign));
Print(nameof(RsaDigitalSign.SignPem), RsaDigitalSign.SignPem(dataToSign, File.ReadAllText("./Keys/privateKey.pem")));
Print(nameof(RsaDigitalSign.SignWithEncryptedPem), RsaDigitalSign.SignWithEncryptedPem(dataToSign, File.ReadAllText("./Keys/encryptedPrivateKey.pem"), "P@ssw0rd"));




//Hmac
Print(nameof(Hmac.GenerateHmacSha256), Hmac.GenerateHmacSha256("Lhwed&lQpl", dataToSign));



return 0;

static void Print(string title, string data) => Console.WriteLine($"{title}\n{data}\n");