using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using CryptoLibrary;
using CipherMode = CryptoLibrary.CipherMode;
using PaddingMode = CryptoLibrary.PaddingMode;

namespace Rijndael
{
    public class ExtendedTests
    {
        public static void RunAllTests()
        {
            Console.WriteLine("=== Extended Rijndael Tests ===\n");

            TestGF256Completeness();
            TestAllModuli();
            TestUserFiles();
            TestAllModesCombinations();
        }

        static void TestGF256Completeness()
        {
            Console.WriteLine("Testing GF(2^8) completeness...");
            var gf256 = new GF256Service();
            var irreducibles = gf256.GetAllIrreduciblePolynomials();

            Console.WriteLine($"Found {irreducibles.Count} irreducible polynomials:");
            foreach (var poly in irreducibles)
            {
                Console.Write($"0x{poly:X2} ");
            }
            Console.WriteLine("\n");

            Console.WriteLine("Testing polynomial factorization:");
            var testPolynomials = new[] { 0x1FF, 0x1FE, 0x1FD, 0x1FC };
            
            foreach (var poly in testPolynomials)
            {
                try
                {
                    var factors = gf256.FactorizePolynomial(poly);
                    Console.WriteLine($"0x{poly:X2} = {string.Join(" * ", factors.Select(f => $"0x{f:X2}"))}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"0x{poly:X2}: Error - {ex.Message}");
                }
            }
            Console.WriteLine();
        }

        static void TestAllModuli()
        {
            Console.WriteLine("Testing encryption with different moduli...");
            var gf256 = new GF256Service();
            var irreducibles = gf256.GetAllIrreduciblePolynomials();

            var testData = Encoding.UTF8.GetBytes("Test message for all moduli");
            var key = new byte[16];
            RandomNumberGenerator.Create().GetBytes(key);

            int successCount = 0;
            foreach (var modulus in irreducibles.Take(10)) 
            {
                try
                {
                    var cipher = new RijndaelCipher(128, 128, modulus);
                    var modeService = new CipherModeService(cipher, 128);
                    cipher.SetKey(key);

                    var encrypted = modeService.Encrypt(testData, CipherMode.ECB, PaddingMode.PKCS7);
                    var decrypted = modeService.Decrypt(encrypted, CipherMode.ECB, PaddingMode.PKCS7);

                    bool success = testData.SequenceEqual(decrypted.Take(testData.Length));
                    if (success) successCount++;

                    Console.WriteLine($"Modulus 0x{modulus:X2}: {(success ? "✓" : "✗")}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Modulus 0x{modulus:X2}: Error - {ex.Message}");
                }
            }
            Console.WriteLine($"Success rate: {successCount}/{Math.Min(10, irreducibles.Count)}\n");
        }

        static void TestUserFiles()
        {
            Console.WriteLine("Testing user file encryption...");
            
            var gf256 = new GF256Service();
            var irreducibles = gf256.GetAllIrreduciblePolynomials();
            var cipher = new RijndaelCipher(128, 128, irreducibles[0]);
            var modeService = new CipherModeService(cipher, 128);

            var key = new byte[16];
            RandomNumberGenerator.Create().GetBytes(key);
            cipher.SetKey(key);

            var testFiles = new[]
            {
                ("./tests/test_text.txt", "text file"),
                ("./tests/test_binary.bin", "binary file"),
                ("./tests/test_image.png", "image file")
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
                        
                        Console.WriteLine($"{description}: {(success ? "✓" : "✗")} ({originalData.Length} -> {encrypted.Length} -> {originalData.Length} bytes)");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"{description}: Error - {ex.Message}");
                    }
                }
            }
            Console.WriteLine();
        }

        static void TestAllModesCombinations()
        {
            Console.WriteLine("Testing all mode/padding combinations...");
            
            var gf256 = new GF256Service();
            var irreducibles = gf256.GetAllIrreduciblePolynomials();
            var cipher = new RijndaelCipher(192, 192, irreducibles[1]);
            var modeService = new CipherModeService(cipher, 192);

            var key = new byte[24];
            RandomNumberGenerator.Create().GetBytes(key);
            cipher.SetKey(key);

            var testData = Encoding.UTF8.GetBytes("This is a comprehensive test message for all encryption modes and padding schemes!");

            var modes = Enum.GetValues<CipherMode>().Where(m => m != CipherMode.PCBC && m != CipherMode.RandomDelta);
            var paddings = Enum.GetValues<PaddingMode>();

            int totalTests = 0, passedTests = 0;

            foreach (var mode in modes)
            {
                foreach (var padding in paddings)
                {
                    totalTests++;
                    try
                    {
                        var iv = mode != CipherMode.ECB ? new byte[24] : null;
                        if (iv != null) RandomNumberGenerator.Create().GetBytes(iv);

                        var encrypted = modeService.Encrypt(testData, mode, padding, iv);
                        var decrypted = modeService.Decrypt(encrypted, mode, padding, iv);

                        bool success = testData.SequenceEqual(decrypted.Take(testData.Length));
                        if (success) passedTests++;

                        Console.WriteLine($"{mode}-{padding}: {(success ? "✓" : "✗")}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"{mode}-{padding}: Error - {ex.Message}");
                    }
                }
            }

            Console.WriteLine($"\nOverall success rate: {passedTests}/{totalTests} ({(double)passedTests/totalTests*100:F1}%)");
        }
    }
}