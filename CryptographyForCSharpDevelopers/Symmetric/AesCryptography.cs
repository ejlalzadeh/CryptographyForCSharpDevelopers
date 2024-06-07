using System.Text;
using System.Security.Cryptography;

namespace CryptographyForCSharpDevelopers.Symmetric;

public class AesCryptography
{
    public static string Encrypt(string plainText, string key, string? iv = null)
    {
        byte[] cipherTextBytes;

        using (Aes aes = Aes.Create())
        {
            aes.Key = Encoding.UTF8.GetBytes(key);
            aes.IV = string.IsNullOrWhiteSpace(iv)
                ? new byte[16]
                : Encoding.ASCII.GetBytes(iv);

            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter streamWriter = new StreamWriter((Stream)cryptoStream))
                    {
                        streamWriter.Write(plainText);
                    }

                    cipherTextBytes = memoryStream.ToArray();
                }
            }
        }

        return Convert.ToBase64String(cipherTextBytes);
    }


    public static string Decrypt(string cipherText, string key, string? iv = null)
    {
        byte[] cipherTextBytes = Convert.FromBase64String(cipherText);

        using (Aes aes = Aes.Create())
        {
            aes.Key = Encoding.UTF8.GetBytes(key);
            aes.IV = string.IsNullOrWhiteSpace(iv)
                ? new byte[16]
                : Encoding.ASCII.GetBytes(iv);

            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            using (MemoryStream memoryStream = new MemoryStream(cipherTextBytes))
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
}