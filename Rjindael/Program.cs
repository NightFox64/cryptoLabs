using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using CryptoLibrary;
using CipherMode = CryptoLibrary.CipherMode;
using PaddingMode = CryptoLibrary.PaddingMode;

namespace Rijndael
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=== Rijndael Implementation Demo ===\n");

            SimpleTest.TestBasicGF256();
            
            Console.WriteLine("\n" + new string('-', 40));

            DemonstrateGF256Operations();

            DemonstrateRijndaelEncryption();

            DemonstrateFileEncryption();

            Console.WriteLine("\n" + new string('=', 50));
            PerformanceTest.TestPowerOptimization();

            Console.WriteLine("\n" + new string('=', 50));
            ExtendedTests.RunAllTests();
        }

        static void DemonstrateGF256Operations()
        {
            Console.WriteLine("1. GF(2^8) Operations Demo");
            Console.WriteLine("==========================");

            var gf256 = new GF256Service();

            byte a = 0x53, b = 0xCA;
            byte sum = gf256.Add(a, b);
            Console.WriteLine($"Add: {a:X2} + {b:X2} = {sum:X2}");

            var irreducibles = gf256.GetAllIrreduciblePolynomials();
            Console.WriteLine($"Found {irreducibles.Count} irreducible polynomials (expected 30)");
            Console.WriteLine($"First few: {string.Join(", ", irreducibles.Take(5).Select(x => $"0x{x:X2}"))}");

            byte modulus = irreducibles[0]; 
            Console.WriteLine($"Using modulus: 0x{modulus:X2}");

            try
            {
                byte product = gf256.Multiply(a, b, modulus);
                Console.WriteLine($"Multiply: {a:X2} * {b:X2} = {product:X2} (mod 0x{modulus:X2})");

                byte inverse = gf256.Inverse(a, modulus);
                Console.WriteLine($"Inverse: {a:X2}^(-1) = {inverse:X2} (mod 0x{modulus:X2})");

                byte verification = gf256.Multiply(a, inverse, modulus);
                Console.WriteLine($"Verification: {a:X2} * {inverse:X2} = {verification:X2} (should be 1)");
            }
            catch (ReducibleModulusException ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }

            Console.WriteLine();
        }

        static void DemonstrateRijndaelEncryption()
        {
            Console.WriteLine("2. Rijndael Encryption Demo");
            Console.WriteLine("===========================");

            var gf256 = new GF256Service();
            var irreducibles = gf256.GetAllIrreduciblePolynomials();
            byte modulus = irreducibles[0]; 

            var configurations = new[]
            {
                (128, 128), (128, 192), (128, 256),
                (192, 128), (192, 192), (192, 256),
                (256, 128), (256, 192), (256, 256)
            };

            foreach (var (blockSize, keySize) in configurations)
            {
                Console.WriteLine($"Testing {blockSize}-bit block, {keySize}-bit key:");

                var cipher = new RijndaelCipher(blockSize, keySize, modulus);
                var modeService = new CipherModeService(cipher, blockSize);

                var key = new byte[keySize / 8];
                RandomNumberGenerator.Create().GetBytes(key);
                cipher.SetKey(key);

                var plaintext = Encoding.UTF8.GetBytes("Hello, Rijndael! This is a test message for encryption.");
                
                var modes = new[] { CipherMode.ECB, CipherMode.CBC, CipherMode.CFB, CipherMode.OFB, CipherMode.CTR };
                var paddings = new[] { PaddingMode.PKCS7, PaddingMode.Zeros };

                foreach (var mode in modes)
                {
                    foreach (var padding in paddings)
                    {
                        try
                        {
                            byte[]? iv = null;
                            if (mode != CipherMode.ECB)
                            {
                                iv = new byte[blockSize / 8];
                                RandomNumberGenerator.Create().GetBytes(iv);
                            }
                            
                            var encrypted = modeService.Encrypt(plaintext, mode, padding, iv);
                            var decrypted = modeService.Decrypt(encrypted, mode, padding, iv);

                            bool success = plaintext.Take(Math.Min(plaintext.Length, decrypted.Length))
                                                   .SequenceEqual(decrypted.Take(Math.Min(plaintext.Length, decrypted.Length)));

                            Console.WriteLine($"  {mode}-{padding}: {(success ? "✓" : "✗")}");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"  {mode}-{padding}: Error - {ex.Message}");
                        }
                    }
                }
                Console.WriteLine();
            }
        }

        static void DemonstrateFileEncryption()
        {
            Console.WriteLine("3. File Encryption Demo");
            Console.WriteLine("=======================");

            var gf256 = new GF256Service();
            var irreducibles = gf256.GetAllIrreduciblePolynomials();
            
            byte modulus = irreducibles[0];
            Console.WriteLine($"Using modulus 0x{modulus:X2}:");

            var cipher = new RijndaelCipher(128, 128, modulus);
            var modeService = new CipherModeService(cipher, 128);

            var key = new byte[16];
            RandomNumberGenerator.Create().GetBytes(key);
            cipher.SetKey(key);

            var testFiles = new[]
            {
                ("./tests/test_text.txt", "text file"),
                ("./tests/test_binary.bin", "binary file"),
                ("./tests/test_image.png", "image file"),
            };

            foreach (var (filename, description) in testFiles)
            {
                if (File.Exists(filename))
                {
                    try
                    {
                        var originalData = File.ReadAllBytes(filename);
                        
                        var iv = new byte[16];
                        RandomNumberGenerator.Create().GetBytes(iv);
                        
                        var encrypted = modeService.Encrypt(originalData, CipherMode.CBC, PaddingMode.PKCS7, iv);
                        var decrypted = modeService.Decrypt(encrypted, CipherMode.CBC, PaddingMode.PKCS7, iv);

                        var trimmedDecrypted = decrypted.Take(originalData.Length).ToArray();
                        bool success = originalData.SequenceEqual(trimmedDecrypted);
                        
                        File.WriteAllBytes($"{filename}.enc", encrypted);
                        File.WriteAllBytes($"{filename}.dec", trimmedDecrypted);

                        Console.WriteLine($"  {description}: {(success ? "✓" : "✗")} " +
                                        $"({originalData.Length} -> {encrypted.Length} -> {originalData.Length} bytes)");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"  {description}: Error - {ex.Message}");
                    }
                }
            }
            Console.WriteLine();
        }
    }
}