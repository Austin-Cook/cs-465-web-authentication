using System.Text;

namespace App.Areas.Identity;

internal static class Utils
{

    /// <summary>
    /// Encoding used to convert strings to and from bytes.
    /// </summary>
    public static Encoding Encoding { get => Encoding.ASCII; }

    /// <summary>
    /// Encodes a salt and a digest into a string.
    /// </summary>
    /// <param name="salt">Salt to encode.</param>
    /// <param name="digest">Digest to encode.</param>
    /// <returns>Encoded salt and digest.</returns>
    public static string EncodeSaltAndDigest(byte[] salt, byte[] digest)
    {
        // todo: Encode as "Base64(salt):Base64(digest)"
        string saltBase64 = Convert.ToBase64String(salt);
        string digestBase64 = Convert.ToBase64String(digest);

        return saltBase64 + ":" + digestBase64;
    }

    /// <summary>
    /// Decodes a salt and a digest from a string.
    /// </summary>
    /// <param name="salt">Salt to decode.</param>
    /// <param name="digest">Digest to decode.</param>
    /// <returns>Decoded salt and digest.</returns>
    public static (byte[], byte[]) DecodeSaltAndDigest(string value)
    {
        // todo: Decode as "Base64(salt):Base64(digest)"
        string[] saltAndDigest = value.Split(':');
        if (saltAndDigest.Length != 2)
        {
            throw new Exception("Error: unable to parse salt and hashed password around ':'");
        }
        byte[] saltBytes = Convert.FromBase64String(saltAndDigest[0]);
        byte[] digestBytes = Convert.FromBase64String(saltAndDigest[1]);

        return (saltBytes, digestBytes);
    }

    public static byte[] StringToBytes(string value)
    {
        return Encoding.UTF8.GetBytes(value);
    }

    public static string BytesToString(byte[] value)
    {
        return Encoding.UTF8.GetString(value);
    }

    /// <summary>
    /// Creates a byte[] with b appended to a.
    /// </summary>
    /// <param name="a">Byte[] to go to the left.</param>
    /// <param name="b">Byte[] to go to the right.</param>
    /// <returns>byte[] with b appended to a.</returns>
    public static byte[] CombineByteArrays(byte[] a, byte[] b)
    {
        byte[] ab = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, ab, 0, a.Length);
        Buffer.BlockCopy(b, 0, ab, a.Length, b.Length);

        return ab;
    }

}
