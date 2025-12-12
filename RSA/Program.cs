using System.Numerics;
using RSA;

class Program
{
    static void Main()
    {
        Console.WriteLine("=== Демонстрация RSA и криптографических алгоритмов ===\n");

        DemonstrateTask1();

        DemonstrateTask2();

        DemonstrateTask3();

        DemonstrateTask4();
    }

    static void DemonstrateTask1()
    {
        Console.WriteLine("=== Задание 1: MathService ===");
        
        Console.WriteLine($"Символ Лежандра (3, 7): {MathService.LegendreSymbol(3, 7)}");
        Console.WriteLine($"Символ Лежандра (2, 7): {MathService.LegendreSymbol(2, 7)}");
        
        Console.WriteLine($"Символ Якоби (3, 9): {MathService.JacobiSymbol(3, 9)}");
        Console.WriteLine($"Символ Якоби (2, 15): {MathService.JacobiSymbol(2, 15)}");
        
        Console.WriteLine($"НОД(48, 18): {MathService.Gcd(48, 18)}");
        
        var (gcd, x, y) = MathService.ExtendedGcd(48, 18);
        Console.WriteLine($"Расширенный НОД(48, 18): gcd={gcd}, x={x}, y={y}");
        Console.WriteLine($"Проверка: 48*{x} + 18*{y} = {48 * x + 18 * y}");
        
        Console.WriteLine($"2^10 mod 1000: {MathService.ModularPow(2, 10, 1000)}");
        Console.WriteLine();
    }

    static void DemonstrateTask2()
    {
        Console.WriteLine("=== Задание 2: Тесты простоты ===");
        
        var testNumbers = new BigInteger[] { 97, 98, 101, 103, 561, 2821 };
        var tests = new IPrimalityTest[]
        {
            new FermatTest(),
            new SolovayStrassenTest(),
            new MillerRabinTest()
        };
        
        foreach (var number in testNumbers)
        {
            Console.WriteLine($"Тестирование числа {number}:");
            foreach (var test in tests)
            {
                var result = test.IsPrime(number, 0.9); 
                Console.WriteLine($"  {test.GetType().Name}: {(result ? "простое" : "составное")}");
            }
            Console.WriteLine();
        }
    }

    static void DemonstrateTask3()
    {
        Console.WriteLine("=== Задание 3: RSA ===");
        
        var rsa = new RSAService(RSAService.PrimalityTestType.MillerRabin, 0.9, 128);
        Console.WriteLine("Генерация ключей...");
        rsa.GenerateNewKeyPair();
        
        var publicKey = rsa.GetPublicKey()!;
        Console.WriteLine($"Открытый ключ: N={publicKey.N}");
        
        var originalText = File.ReadAllText("tests/test.txt");
        Console.WriteLine($"Исходный файл: {originalText.Length} символов");
        
        var encryptedData = EncryptFile(rsa, originalText);
        File.WriteAllText("./tests/test_encrypted.txt", string.Join(",", encryptedData));
        Console.WriteLine("Файл зашифрован в test_encrypted.txt");
        
        var decryptedText = DecryptFile(rsa, encryptedData);
        File.WriteAllText("./tests/test_decrypted.txt", decryptedText);
        Console.WriteLine("Файл расшифрован в test_decrypted.txt");
        
        var filesMatch = originalText == decryptedText;
        Console.WriteLine($"Файлы совпадают: {filesMatch}");
        Console.WriteLine();

        var originalImageBytes = File.ReadAllBytes("tests/testImage.png");
        Console.WriteLine($"Исходный файл: {originalImageBytes.Length} байт");
        
        var encryptedImageData = EncryptBytes(rsa, originalImageBytes);
        File.WriteAllText("tests/testImage_encrypted.txt", string.Join(",", encryptedImageData));
        Console.WriteLine("Файл зашифрован в testImage_encrypted.txt");
        
        var decryptedImageBytes = DecryptBytes(rsa, encryptedImageData);
        File.WriteAllBytes("tests/testImage_decrypted.png", decryptedImageBytes);
        Console.WriteLine("Файл расшифрован в testImage_decrypted.png");
        
        var filesMatchImage = originalImageBytes.SequenceEqual(decryptedImageBytes);
        Console.WriteLine($"Файлы совпадают: {filesMatchImage}");
        Console.WriteLine();
    }
    
    static List<BigInteger> EncryptFile(RSAService rsa, string text)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(text);
        var encrypted = new List<BigInteger>();
        
        foreach (var b in bytes)
        {
            encrypted.Add(rsa.Encrypt(b));
        }
        
        return encrypted;
    }
    
    static string DecryptFile(RSAService rsa, List<BigInteger> encryptedData)
    {
        var bytes = new List<byte>();
        
        foreach (var encrypted in encryptedData)
        {
            bytes.Add((byte)rsa.Decrypt(encrypted));
        }
        
        return System.Text.Encoding.UTF8.GetString(bytes.ToArray());
    }
    
    static List<BigInteger> EncryptBytes(RSAService rsa, byte[] bytes)
    {
        var encrypted = new List<BigInteger>();
        
        foreach (var b in bytes)
        {
            encrypted.Add(rsa.Encrypt(b));
        }
        
        return encrypted;
    }
    
    static byte[] DecryptBytes(RSAService rsa, List<BigInteger> encryptedData)
    {
        var bytes = new List<byte>();
        
        foreach (var encrypted in encryptedData)
        {
            bytes.Add((byte)rsa.Decrypt(encrypted));
        }
        
        return bytes.ToArray();
    }

    static void DemonstrateTask4()
    {
        Console.WriteLine("=== Задание 4: Атака Винера ===");
        
        var vulnerableKey = CreateVulnerableKey();
        Console.WriteLine($"Уязвимый ключ: N={vulnerableKey.N}, E={vulnerableKey.E}");
        
        var result = WienerAttackService.PerformAttack(vulnerableKey);
        
        if (result.D.HasValue)
        {
            Console.WriteLine($"Атака успешна!");
            Console.WriteLine($"Найденная экспонента d: {result.D}");
            Console.WriteLine($"Найденная функция Эйлера φ(n): {result.Phi}");
            Console.WriteLine($"Количество подходящих дробей: {result.ContinuedFractions.Count}");
        }
        else
        {
            Console.WriteLine("Атака не удалась");
            Console.WriteLine($"Проверено подходящих дробей: {result.ContinuedFractions.Count}");
        }
    }

    static RSAPublicKey CreateVulnerableKey()
    {
        BigInteger p = 61;
        BigInteger q = 53;
        BigInteger n = p * q;
        BigInteger phi = (p - 1) * (q - 1);
        BigInteger d = 7;
        
        var (gcd, e, _) = MathService.ExtendedGcd(d, phi);
        e = ((e % phi) + phi) % phi;
        
        Console.WriteLine($"Создан уязвимый ключ: p={p}, q={q}, d={d}");
        return new RSAPublicKey(n, e);
    }
}