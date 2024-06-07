using System.Security.Cryptography;
using System.Text;

namespace CryptographyForCSharpDevelopers.Symmetric;

public class AesCryptography
{
    public static string Decrypt(string cipherText, string primaryKey, string? secondaryKey = null)
    {
        byte[] iv = new byte[16];

        if (!string.IsNullOrWhiteSpace(secondaryKey))
            iv = Encoding.ASCII.GetBytes(secondaryKey);

        byte[] buffer = Convert.FromBase64String(cipherText);
        using (Aes aes = Aes.Create())
        {
            aes.Key = Encoding.UTF8.GetBytes(primaryKey); aes.IV = iv;
            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using (MemoryStream memoryStream = new MemoryStream(buffer))
            {
                using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader streamReader = new StreamReader((Stream)cryptoStream))
                    {
                        return streamReader.ReadToEnd();
                    }
                }
            }
        }
    }

    public static string Encrypt(string plainText, string primaryKey, string? secondaryKey = null)
    {
        byte[] iv = new byte[16];

        if (!string.IsNullOrWhiteSpace(secondaryKey))
            iv = Encoding.ASCII.GetBytes(secondaryKey);

        byte[] array;
        using (Aes aes = Aes.Create())
        {
            aes.Key = Encoding.UTF8.GetBytes(primaryKey);
            aes.IV = iv;
            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter streamWriter = new StreamWriter((Stream)cryptoStream))
                    {
                        streamWriter.Write(plainText);
                    }
                    array = memoryStream.ToArray();
                }
            }
        }
        return Convert.ToBase64String(array);
    }
}