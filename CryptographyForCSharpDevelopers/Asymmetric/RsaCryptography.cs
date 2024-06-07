using System.Security.Cryptography;
using System.Text;

namespace CryptographyForCSharpDevelopers.Asymmetric;

public class RsaCryptography
{
    public static string Encrypt(string data, string publicKey)
    {
        RSA rsa = RSA.Create();
        rsa.ImportFromPem(publicKey);
        byte[] cipherBytes = rsa.Encrypt(Encoding.UTF8.GetBytes(data), RSAEncryptionPadding.Pkcs1);

        return Convert.ToBase64String(cipherBytes);
    }

    public static string Decrypt(string data, string privateKey)
    {
        RSA rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(Encoding.ASCII.GetBytes(privateKey), out _);
        byte[] plainTextBytes = rsa.Decrypt(Encoding.UTF8.GetBytes(data), RSAEncryptionPadding.Pkcs1);

        return Convert.ToBase64String(plainTextBytes);
    }
}