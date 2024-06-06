using System.Security.Cryptography;
using System.Text;

namespace CryptographyForCSharpDevelopers.HMAC;

public static class Hmac
{
    public static string GenerateHmacSha256(string key, string data)
    {
        using HMACSHA256 hmacSha256 = new HMACSHA256(Encoding.UTF8.GetBytes(key));

        byte[] hmacBytes = hmacSha256.ComputeHash(Encoding.UTF8.GetBytes(data));

        return Convert.ToBase64String(hmacBytes);
    }
}