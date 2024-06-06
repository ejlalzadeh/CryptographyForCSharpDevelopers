using System.Security.Cryptography;
using System.Text;
using CryptographyForCSharpDevelopers.Hashing;

namespace CryptographyForCSharpDevelopers.DigitalSign;

public class RsaDigitalSign
{
    public static string Sign(string dataToSign)
    {
        using RSA rsa = RSA.Create();

        RSAParameters parameters = rsa.ExportParameters(true);
        string publicKeyPem = rsa.ExportSubjectPublicKeyInfoPem();
        string privateKeyPem = rsa.ExportRSAPrivateKeyPem();

        RSAPKCS1SignatureFormatter rsaFormatter = new(rsa);
        rsaFormatter.SetHashAlgorithm(HashAlgorithmName.SHA256.ToString());

        byte[] signedHash = rsaFormatter.CreateSignature(Hashing.Hashing.GenerateSha256Hash(dataToSign));

        return Convert.ToBase64String(signedHash);
    }

    public static string SignPem(string dataToSign, string privateKeyPem)
    {
        using RSA rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);

        RSAPKCS1SignatureFormatter rsaFormatter = new(rsa);
        rsaFormatter.SetHashAlgorithm(HashAlgorithmName.SHA256.ToString());

        byte[] signedHash = rsaFormatter.CreateSignature(Hashing.Hashing.GenerateSha256Hash(dataToSign));

        return Convert.ToBase64String(signedHash);
    }

    public static string SignWithEncryptedPem(string dataToSign, string encryptedPrivateKeyPem, string privateKeyPassword)
    {
        using RSA rsa = RSA.Create();
        rsa.ImportFromEncryptedPem(encryptedPrivateKeyPem.AsSpan(), privateKeyPassword.AsSpan());

        RSAPKCS1SignatureFormatter rsaFormatter = new(rsa);
        rsaFormatter.SetHashAlgorithm(HashAlgorithmName.SHA256.ToString());

        byte[] signedHash = rsaFormatter.CreateSignature(Hashing.Hashing.GenerateSha256Hash(dataToSign));

        return Convert.ToBase64String(signedHash);
    }

    public static bool VerifyPem(string originalData, string signedData, string publicKeyPem)
    {
        using RSA rsa = RSA.Create();
        rsa.ImportFromPem(publicKeyPem);

        RSAPKCS1SignatureDeformatter deFormatter = new(rsa);
        deFormatter.SetHashAlgorithm(HashAlgorithmName.SHA256.ToString());

        return deFormatter.VerifySignature(Hashing.Hashing.GenerateSha256Hash(originalData), Convert.FromBase64String(signedData));
    }

    public static bool VerifyPemPure(string originalData, string signedData, string publicKeyPem)
    {
        using RSA rsa = RSA.Create();
        rsa.ImportFromPem(publicKeyPem);

        return rsa.VerifyData(Encoding.UTF8.GetBytes(originalData), Convert.FromBase64String(signedData), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
}