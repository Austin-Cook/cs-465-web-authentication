using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Konscious.Security.Cryptography;

namespace App.Areas.Identity;

/// <summary>
/// Password hasher backed by Argon2id.
/// </summary>
/// <remarks>
/// For reference, consider the <see href="https://github.com/aspnet/AspNetIdentity/blob/main/src/Microsoft.AspNet.Identity.Core/PasswordHasher.cs">default implementation</see>
/// </remarks>
internal class Argon2idHasher : IPasswordHasher<IdentityUser>
{

    /// <summary>
    /// Hash a password using Argon2id.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <returns>String containing all the information needed to verify the password in the future.</returns>
    public string HashPassword(IdentityUser user, string password)
    {
        // get password bytes
        byte[] passwordBytes = Utils.StringToBytes(password);

        // Use a random 32-byte salt. Use a 32-byte digest.
        byte[] salt = Utils.Get32ByteSalt();

        // Degrees of parallelism is 8, iterations is 4, and memory size is 128MB.
        var argon2 = new Argon2id(passwordBytes)
        {
            DegreeOfParallelism = 8,
            Iterations = 4,
            MemorySize = 128 * 1024,
            Salt = salt
        };
        byte[] digest = argon2.GetBytes(32);

        // Encode as "Base64(salt):Base64(digest)"
        return Utils.EncodeSaltAndDigest(salt, digest);
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

        // Degrees of parallelism is 8, iterations is 4, and memory size is 128MB.
        var argon2 = new Argon2id(providedPasswordBytes)
        {
            DegreeOfParallelism = 8,
            Iterations = 4,
            MemorySize = 128 * 1024,
            Salt = salt
        };
        byte[] actualDigest = argon2.GetBytes(32);

        Console.WriteLine("salt: " + Convert.ToBase64String(salt));
        Console.WriteLine("expected password hash: " + Convert.ToBase64String(expectedDigest));
        Console.WriteLine("actual password hash: " + Convert.ToBase64String(actualDigest));

        if (expectedDigest.SequenceEqual(actualDigest))
        {
            return PasswordVerificationResult.Success;
        }
        return PasswordVerificationResult.Failed;
    }
}