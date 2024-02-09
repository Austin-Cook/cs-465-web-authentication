using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

namespace App.Areas.Identity;

/// <summary>
/// Password hasher backed by PBKDF2.
/// </summary>
/// <remarks>
/// For reference, consider the <see href="https://github.com/aspnet/AspNetIdentity/blob/main/src/Microsoft.AspNet.Identity.Core/PasswordHasher.cs">default implementation</see>
/// </remarks>
internal class PBKDF2Hasher : IPasswordHasher<IdentityUser>
{
    readonly int numIterations = 100000;

    /// <summary>
    /// Hash a password using PBKDF2.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <returns>String containing all the information needed to verify the password in the future.</returns>
    public string HashPassword(IdentityUser user, string password)
    {
        // get password bytes
        byte[] passwordBytes = Utils.StringToBytes(password);

        // Use a random 32-byte salt. Use a 32-byte digest.
        byte[] salt = Utils.Get32ByteSalt();

        // todo: Use 100,000 iterations and the SHA256 algorithm.
        byte[] digest = Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, numIterations, HashAlgorithmName.SHA256, 32);

        // Encode as "Base64(salt):Base64(digest)"
        string saltAndDigest = Utils.EncodeSaltAndDigest(salt, digest);

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
        byte[] actualDigest = Rfc2898DeriveBytes.Pbkdf2(providedPasswordBytes, salt, numIterations, HashAlgorithmName.SHA256, 32);

        if (expectedDigest.SequenceEqual(actualDigest))
        {
            return PasswordVerificationResult.Success;
        }
        return PasswordVerificationResult.Failed;
    }
}