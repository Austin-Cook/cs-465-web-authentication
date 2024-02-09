using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

namespace App.Areas.Identity;

/// <summary>
/// Password hasher backed by iterative SHA256 hashing.
/// </summary>
/// <remarks>
/// For reference, consider the <see href="https://github.com/aspnet/AspNetIdentity/blob/main/src/Microsoft.AspNet.Identity.Core/PasswordHasher.cs">default implementation</see>
/// </remarks>
internal class IterativeHasher : IPasswordHasher<IdentityUser>
{
    readonly int numIterations = 100000;

    /// <summary>
    /// Hash a password using iterative SHA256 hashing.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <returns>String containing all the information needed to verify the password in the future.</returns>
    public string HashPassword(IdentityUser user, string password)
    {
        // get password bytes
        byte[] passwordBytes = Utils.StringToBytes(password);

        // Use a random 32-byte salt. Use a 32-byte digest.
        Random rnd = new();
        byte[] salt = new byte[32];
        rnd.NextBytes(salt);

        // copy passwordBytes and salt into the digest
        byte[] digest = Utils.CombineByteArrays(salt, passwordBytes);
        // 100,000 iterations and the SHA256 algorithm.
        for (int i = 0; i < numIterations; i++)
        {
            digest = SHA256.HashData(digest);
        }

        // Encode as "Base64(salt):Base64(digest)"
        string saltAndDigest = Utils.EncodeSaltAndDigest(salt, digest);
        Console.WriteLine("Hashed a new password:");
        Console.WriteLine(saltAndDigest);
        return saltAndDigest;
    }

    /// <summary>
    /// Verify that a password matches the hashed password.
    /// </summary>
    /// <param name="hashedPassword">Hashed password value stored when registering.</param>
    /// <param name="providedPassword">Password provided by user in login attempt.</param>
    /// <returns></returns>
    public PasswordVerificationResult VerifyHashedPassword(IdentityUser user, string hashedPassword, string providedPassword)
    {
        (byte[] salt, byte[] expectedDigest) = Utils.DecodeSaltAndDigest(hashedPassword);

        // compute hash of providedPassword
        byte[] providedPasswordBytes = Utils.StringToBytes(providedPassword);

        // byte[] actualDigest = SHA256.HashData(saltedProvidedPasswordByes);
        byte[] actualDigest = Utils.CombineByteArrays(salt, providedPasswordBytes);
        for (int i = 0; i < numIterations; i++)
        {
            actualDigest = SHA256.HashData(actualDigest);
        }

        if (expectedDigest.SequenceEqual(actualDigest))
        {
            return PasswordVerificationResult.Success;
        }
        Console.WriteLine("Verify(failed) actual computed digest:");
        Console.WriteLine(Convert.ToBase64String(actualDigest));

        return PasswordVerificationResult.Failed;
    }
}
