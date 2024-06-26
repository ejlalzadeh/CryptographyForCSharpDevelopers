﻿using System.Security.Cryptography;
using CryptographyForCSharpDevelopers.Asymmetric;
using CryptographyForCSharpDevelopers.DigitalSign;
using CryptographyForCSharpDevelopers.Hashing;
using CryptographyForCSharpDevelopers.HMAC;
using CryptographyForCSharpDevelopers.Symmetric;

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


//AES
string aesEncrypted = AesCryptography.Encrypt(dataToSign, "QbGdMd018Vg24mpf0JkTg4SGSKDJHuHA");
Print(nameof(AesCryptography.Encrypt), aesEncrypted);
Print(nameof(AesCryptography.Decrypt), AesCryptography.Decrypt(aesEncrypted, "QbGdMd018Vg24mpf0JkTg4SGSKDJHuHA"));



//RSA
string rsaEncrypted = RsaCryptography.Encrypt(dataToSign, File.ReadAllText("./Keys/publicKey.pem"));
Print(nameof(RsaCryptography.Encrypt), rsaEncrypted);

string rsaDecrypted = RsaCryptography.Decrypt(rsaEncrypted, File.ReadAllText("./Keys/privateKey.pem"));
Print(nameof(RsaCryptography.Decrypt), rsaDecrypted);