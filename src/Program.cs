using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AesGcmSample
{
    internal static class Program
    {
        private const string KeyInBase64 = "hkraH8g3WrYO4BVN6tTk5p9UCO20NFbWC0Wi5vRl0PI=";

        public static async Task Main()
        {
            var plaintextBytes = await File.ReadAllBytesAsync("test-data.xlsx");
            var plaintext = Convert.ToBase64String(plaintextBytes);

            var keyInBytes = Convert.FromBase64String(KeyInBase64);
            var (ciphertext, nonce, tag) = Encrypt(plaintext, keyInBytes);

            const string encryptedFileName = "test-data-encrypted.xlsx";
            await File.WriteAllBytesAsync(encryptedFileName, ciphertext);

            var nonceAndTagFileName = $"{encryptedFileName.Replace(".xlsx", string.Empty)}_nonce_tag.txt";
            await File.WriteAllLinesAsync(
                nonceAndTagFileName,
                new[] {Convert.ToBase64String(nonce), Convert.ToBase64String(tag)}
            );

            var encryptedFileBytes = await File.ReadAllBytesAsync(encryptedFileName);
            
            var nonceAndTagFile = await File.ReadAllLinesAsync(nonceAndTagFileName);
            var nonceInBytes = Convert.FromBase64String(nonceAndTagFile[0]);
            var tagInBytes = Convert.FromBase64String(nonceAndTagFile[1]);

            var decryptedPlaintext = Decrypt(
                encryptedFileBytes,
                nonceInBytes,
                tagInBytes,
                keyInBytes);
            
            Console.WriteLine(decryptedPlaintext.Equals(plaintext) ? "Decryption successful!" : "Error!");
        }

        private static (byte[] ciphertext, byte[] nonce, byte[] tag) Encrypt(string plaintext, byte[] key)
        {
            using var aes = new AesGcm(key);
            var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
            RandomNumberGenerator.Fill(nonce);

            var tag = new byte[AesGcm.TagByteSizes.MaxSize];

            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            var ciphertext = new byte[plaintextBytes.Length];

            aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

            return (ciphertext, nonce, tag);
        }

        private static string Decrypt(byte[] ciphertext, byte[] nonce, byte[] tag, byte[] key)
        {
            using var aes = new AesGcm(key);
            var plaintextBytes = new byte[ciphertext.Length];

            aes.Decrypt(nonce, ciphertext, tag, plaintextBytes);

            return Encoding.UTF8.GetString(plaintextBytes);
        }
    }
}