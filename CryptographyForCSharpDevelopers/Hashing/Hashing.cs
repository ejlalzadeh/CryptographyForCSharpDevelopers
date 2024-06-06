using System.Security.Cryptography;
using System.Text;

namespace CryptographyForCSharpDevelopers.Hashing;

public static class Hashing
{
    public static byte[] GenerateSha256Hash(string data)
    {
        byte[] dataBytes = Encoding.UTF8.GetBytes(data);

        using SHA256 sha256 = SHA256.Create();
        return sha256.ComputeHash(dataBytes);
    }

    public static string GenerateSha256HashString(string data)
    {
        byte[] dataBytes = Encoding.UTF8.GetBytes(data);

        using SHA256 sha256 = SHA256.Create();
        return Convert.ToBase64String(sha256.ComputeHash(dataBytes));
    }
}