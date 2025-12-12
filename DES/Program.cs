using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoLibrary
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("=== Демонстрация криптографических алгоритмов DES и DEAL ===\n");

            // Создаем тестовые данные
            await CreateTestFiles();

            // Тестируем DES
            await TestDES();

            // Тестируем DEAL
            await TestDEAL();

            // Тестируем перестановку битов
            await TestBitPermutation();

            Console.WriteLine("\nДемонстрация завершена!");
        }

        static async Task CreateTestFiles()
        {
            Console.WriteLine("Создание тестовых файлов...");

            Directory.CreateDirectory("test_files");

            await File.WriteAllTextAsync("test_files/text.txt", 
                "Это тестовый текстовый файл для демонстрации шифрования. " +
                "Он содержит различные символы и достаточно длинный для тестирования различных режимов шифрования.");

            var rng = new Random(42); 
            byte[] randomData = new byte[1024];
            rng.NextBytes(randomData);
            await File.WriteAllBytesAsync("test_files/random.bin", randomData);

            byte[] bmpData = CreateSimpleBMP();
            await File.WriteAllBytesAsync("test_files/image.bmp", bmpData);

            if (!File.Exists("test_files/user_test.bin"))
            {
                byte[] userData = Encoding.UTF8.GetBytes("Пользователь может изменить содержимое этого файла для тестирования.");
                await File.WriteAllBytesAsync("test_files/user_test.bin", userData);
            }

            Console.WriteLine("Тестовые файлы созданы.\n");
        }

        static byte[] CreateSimpleBMP()
        {
            byte[] header = {
                0x42, 0x4D, 0x46, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x36, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x08, 0x00,
                0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x18, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            };

            byte[] pixels = new byte[64 * 3]; 
            for (int i = 0; i < pixels.Length; i += 3)
            {
                pixels[i] = (byte)(i % 256);   
                pixels[i + 1] = (byte)((i + 1) % 256);
                pixels[i + 2] = (byte)((i + 2) % 256);
            }

            byte[] result = new byte[header.Length + pixels.Length];
            Array.Copy(header, result, header.Length);
            Array.Copy(pixels, 0, result, header.Length, pixels.Length);
            return result;
        }

        static async Task TestDES()
        {
            Console.WriteLine("=== Тестирование DES ===");

            var des = new DES();
            byte[] key = { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
            des.SetKey(key);

            Console.WriteLine("Тест базового шифрования DES:");
            byte[] plaintext = Encoding.UTF8.GetBytes("HELLO123");
            Array.Resize(ref plaintext, 8);
            
            byte[] encrypted = des.Encrypt(plaintext);
            byte[] decrypted = des.Decrypt(encrypted);

            Console.WriteLine($"Исходный текст: {BitConverter.ToString(plaintext)}");
            Console.WriteLine($"Зашифрованный: {BitConverter.ToString(encrypted)}");
            Console.WriteLine($"Расшифрованный: {BitConverter.ToString(decrypted)}");
            Console.WriteLine($"Совпадение: {BitConverter.ToString(plaintext) == BitConverter.ToString(decrypted)}\n");

            await TestCipherModes(des, "DES");
            
            await TestDESComponents();
        }

        static async Task TestDEAL()
        {
            Console.WriteLine("=== Тестирование DEAL ===");

            var deal = new DEAL();
            byte[] key = {
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
            };
            deal.SetKey(key);

            Console.WriteLine("Тест базового шифрования DEAL:");
            byte[] plaintext = Encoding.UTF8.GetBytes("HELLO123");
            Array.Resize(ref plaintext, 8); 
            
            byte[] encrypted = deal.Encrypt(plaintext);
            byte[] decrypted = deal.Decrypt(encrypted);

            Console.WriteLine($"Исходный текст: {BitConverter.ToString(plaintext)}");
            Console.WriteLine($"Зашифрованный: {BitConverter.ToString(encrypted)}");
            Console.WriteLine($"Расшифрованный: {BitConverter.ToString(decrypted)}");
            Console.WriteLine($"Совпадение: {BitConverter.ToString(plaintext) == BitConverter.ToString(decrypted)}\n");

            await TestCipherModes(deal, "DEAL");
            
            await TestDEALComponents();
        }

        static async Task TestCipherModes(ISymmetricCipher cipher, string algorithmName)
        {
            Console.WriteLine($"Тестирование режимов шифрования для {algorithmName}:");

            byte[] key = algorithmName == "DES" 
                ? new byte[] { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 }
                : new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                              0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };

            var modes = new[] { CipherMode.ECB, CipherMode.CBC, CipherMode.CFB, CipherMode.OFB, CipherMode.CTR };
            var paddings = new[] { PaddingMode.PKCS7, PaddingMode.Zeros };

            foreach (var mode in modes)
            {
                foreach (var padding in paddings)
                {
                    try
                    {
                        Console.WriteLine($"  Режим: {mode}, Набивка: {padding}");

                        var context = new ImprovedCryptoContext(cipher, key, mode, padding, 8);

                        await context.EncryptFileAsync("test_files/text.txt", $"test_files/text_{algorithmName}_{mode}_{padding}.enc");
                        await context.DecryptFileAsync($"test_files/text_{algorithmName}_{mode}_{padding}.enc", $"test_files/text_{algorithmName}_{mode}_{padding}.dec");

                        byte[] original = await File.ReadAllBytesAsync("test_files/text.txt");
                        byte[] decrypted = await File.ReadAllBytesAsync($"test_files/text_{algorithmName}_{mode}_{padding}.dec");
                        
                        bool isCorrect = CompareArrays(original, decrypted);
                        Console.WriteLine($"    Текстовый файл: {(isCorrect ? "OK" : "ОШИБКА")}");

                        await context.EncryptFileAsync("test_files/random.bin", $"test_files/random_{algorithmName}_{mode}_{padding}.enc");
                        await context.DecryptFileAsync($"test_files/random_{algorithmName}_{mode}_{padding}.enc", $"test_files/random_{algorithmName}_{mode}_{padding}.dec");

                        original = await File.ReadAllBytesAsync("test_files/random.bin");
                        decrypted = await File.ReadAllBytesAsync($"test_files/random_{algorithmName}_{mode}_{padding}.dec");
                        
                        isCorrect = CompareArrays(original, decrypted);
                        Console.WriteLine($"    Бинарный файл: {(isCorrect ? "OK" : "ОШИБКА")}");

                        await context.EncryptFileAsync("test_files/image.bmp", $"test_files/image_{algorithmName}_{mode}_{padding}.enc");
                        await context.DecryptFileAsync($"test_files/image_{algorithmName}_{mode}_{padding}.enc", $"test_files/image_{algorithmName}_{mode}_{padding}.dec");

                        original = await File.ReadAllBytesAsync("test_files/image.bmp");
                        decrypted = await File.ReadAllBytesAsync($"test_files/image_{algorithmName}_{mode}_{padding}.dec");
                        
                        isCorrect = CompareArrays(original, decrypted);
                        Console.WriteLine($"    Изображение: {(isCorrect ? "OK" : "ОШИБКА")}");

                        if (File.Exists("test_files/user_test.bin"))
                        {
                            await context.EncryptFileAsync("test_files/user_test.bin", $"test_files/user_test_{algorithmName}_{mode}_{padding}.enc");
                            await context.DecryptFileAsync($"test_files/user_test_{algorithmName}_{mode}_{padding}.enc", $"test_files/user_test_{algorithmName}_{mode}_{padding}.dec");

                            original = await File.ReadAllBytesAsync("test_files/user_test.bin");
                            decrypted = await File.ReadAllBytesAsync($"test_files/user_test_{algorithmName}_{mode}_{padding}.dec");
                            
                            isCorrect = CompareArrays(original, decrypted);
                            Console.WriteLine($"    Пользовательский файл: {(isCorrect ? "OK" : "ОШИБКА")}");
                        }

                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"    Ошибка: {ex.Message}");
                    }
                }
            }
            Console.WriteLine();
        }

        static bool CompareArrays(byte[] array1, byte[] array2)
        {
            if (array1.Length != array2.Length)
                return false;

            for (int i = 0; i < array1.Length; i++)
            {
                if (array1[i] != array2[i])
                    return false;
            }
            return true;
        }

        static async Task TestBitPermutation()
        {
            Console.WriteLine("=== Тестирование функции перестановки битов ===");

            byte[] input = { 0xAB, 0xCD };
            int[] permutation = { 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };

            byte[] result1 = BitPermutation.PerformPermutation(input, permutation, true, true);
            byte[] result2 = BitPermutation.PerformPermutation(input, permutation, false, false);

            Console.WriteLine($"Входные данные: {BitConverter.ToString(input)}");
            Console.WriteLine($"Результат (LSB first, 0-based): {BitConverter.ToString(result1)}");
            Console.WriteLine($"Результат (MSB first, 1-based): {BitConverter.ToString(result2)}");
            Console.WriteLine();
        }

        static async Task TestDESComponents()
        {
            Console.WriteLine("=== Тестирование компонентов DES ===");

            var keyExpansion = new DESKeyExpansion();
            byte[] testKey = { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
            byte[][] roundKeys = keyExpansion.GenerateRoundKeys(testKey);
            
            Console.WriteLine($"Мастер-ключ: {BitConverter.ToString(testKey)}");
            Console.WriteLine($"Количество раундовых ключей: {roundKeys.Length}");
            for (int i = 0; i < Math.Min(3, roundKeys.Length); i++)
            {
                Console.WriteLine($"Раундовый ключ {i + 1}: {BitConverter.ToString(roundKeys[i])}");
            }

            var roundFunction = new DESRoundFunction();
            byte[] testBlock = { 0x12, 0x34, 0x56, 0x78 };
            byte[] testRoundKey = roundKeys[0];
            byte[] roundResult = roundFunction.Transform(testBlock, testRoundKey);
            
            Console.WriteLine($"Тестовый блок: {BitConverter.ToString(testBlock)}");
            Console.WriteLine($"Результат раундовой функции: {BitConverter.ToString(roundResult)}");

            var feistelNetwork = new FeistelNetwork(keyExpansion, roundFunction, 16);
            feistelNetwork.SetKey(testKey);
            byte[] feistelInput = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
            byte[] feistelEncrypted = feistelNetwork.Encrypt(feistelInput);
            byte[] feistelDecrypted = feistelNetwork.Decrypt(feistelEncrypted);
            
            Console.WriteLine($"Вход сети Фейстеля: {BitConverter.ToString(feistelInput)}");
            Console.WriteLine($"Выход сети Фейстеля: {BitConverter.ToString(feistelEncrypted)}");
            Console.WriteLine($"Расшифровано: {BitConverter.ToString(feistelDecrypted)}");
            Console.WriteLine($"Корректность: {BitConverter.ToString(feistelInput) == BitConverter.ToString(feistelDecrypted)}\n");
        }

        static async Task TestDEALComponents()
        {
            Console.WriteLine("=== Тестирование компонентов DEAL ===");

            var desAdapter = new DESAdapter();
            byte[] desKey = { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
            byte[] desInput = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
            byte[] desResult = desAdapter.Transform(desInput, desKey);
            
            Console.WriteLine($"DES адаптер - вход: {BitConverter.ToString(desInput)}");
            Console.WriteLine($"DES адаптер - выход: {BitConverter.ToString(desResult)}");

            var dealKeyExpansion = new DEALKeyExpansion();
            byte[] dealMasterKey = {
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
            };
            byte[][] dealRoundKeys = dealKeyExpansion.GenerateRoundKeys(dealMasterKey);
            
            Console.WriteLine($"DEAL мастер-ключ: {BitConverter.ToString(dealMasterKey)}");
            Console.WriteLine($"Количество раундовых ключей: {dealRoundKeys.Length}");
            for (int i = 0; i < dealRoundKeys.Length; i++)
            {
                Console.WriteLine($"DEAL раундовый ключ {i + 1}: {BitConverter.ToString(dealRoundKeys[i])}");
            }

            var dealRoundFunction = new DEALRoundFunction();
            byte[] dealTestBlock = { 0x12, 0x34, 0x56, 0x78 };
            byte[] dealRoundResult = dealRoundFunction.Transform(dealTestBlock, dealRoundKeys[0]);
            
            Console.WriteLine($"DEAL тестовый блок: {BitConverter.ToString(dealTestBlock)}");
            Console.WriteLine($"DEAL результат раундовой функции: {BitConverter.ToString(dealRoundResult)}");
            Console.WriteLine();
        }
    }
}