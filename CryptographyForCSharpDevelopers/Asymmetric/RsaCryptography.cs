using System.Security.Cryptography;
using System.Text;

namespace CryptographyForCSharpDevelopers.Asymmetric;

public class RsaCryptography
{
    public static string Encrypt(string plainText, string publicKey)
    {
        RSA rsa = RSA.Create();
        rsa.ImportFromPem(publicKey);
        byte[] cipherBytes = rsa.Encrypt(Encoding.UTF8.GetBytes(plainText), RSAEncryptionPadding.Pkcs1);

        return Convert.ToBase64String(cipherBytes);
    }

    public static string Decrypt(string cipherText, string privateKey)
    {
        RSA rsa = RSA.Create();
        rsa.ImportFromPem(privateKey);
        byte[] plainTextBytes = rsa.Decrypt(Convert.FromBase64String(cipherText), RSAEncryptionPadding.Pkcs1);

        return Encoding.Default.GetString(plainTextBytes);
    }
}