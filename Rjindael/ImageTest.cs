using System;
using System.IO;
using System.Security.Cryptography;
using CryptoLibrary;
using CipherMode = CryptoLibrary.CipherMode;
using PaddingMode = CryptoLibrary.PaddingMode;

namespace Rijndael
{
    public static class ImageTest
    {
        public static void TestImageEncryption()
        {
            Console.WriteLine("Testing image encryption/decryption...");
            
            var gf256 = new GF256Service();
            var irreducibles = gf256.GetAllIrreduciblePolynomials();
            var cipher = new RijndaelCipher(128, 128, irreducibles[0]);
            var modeService = new CipherModeService(cipher, 128);

            var key = new byte[16];
            var iv = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
                rng.GetBytes(iv);
            }
            cipher.SetKey(key);

            string imagePath = "./tests/test_image.png";
            if (!File.Exists(imagePath))
            {
                Console.WriteLine("Image file not found");
                return;
            }

            var originalData = File.ReadAllBytes(imagePath);
            Console.WriteLine($"Original size: {originalData.Length} bytes");

            var encrypted = modeService.Encrypt(originalData, CipherMode.CBC, PaddingMode.PKCS7, iv);
            Console.WriteLine($"Encrypted size: {encrypted.Length} bytes");

            var decrypted = modeService.Decrypt(encrypted, CipherMode.CBC, PaddingMode.PKCS7, iv);
            Console.WriteLine($"Decrypted size: {decrypted.Length} bytes");

            var actualDecrypted = new byte[originalData.Length];
            Array.Copy(decrypted, actualDecrypted, originalData.Length);

            bool success = true;
            for (int i = 0; i < originalData.Length; i++)
            {
                if (originalData[i] != actualDecrypted[i])
                {
                    success = false;
                    Console.WriteLine($"Mismatch at byte {i}: {originalData[i]} != {actualDecrypted[i]}");
                    break;
                }
            }

            File.WriteAllBytes($"{imagePath}.enc", encrypted);
            File.WriteAllBytes($"{imagePath}.dec", actualDecrypted);

            Console.WriteLine($"Image test: {(success ? "✓" : "✗")}");
        }
    }
}