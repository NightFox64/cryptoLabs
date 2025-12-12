using System.Numerics;

namespace RSA;

public class RSAService
{
    public enum PrimalityTestType { Fermat, SolovayStrassen, MillerRabin }

    public class KeyGenerator
    {
        private readonly IPrimalityTest _primalityTest;
        private readonly double _minProbability;
        private readonly int _bitLength;
        private static readonly Random _random = new();

        public KeyGenerator(PrimalityTestType testType, double minProbability, int bitLength)
        {
            _primalityTest = testType switch
            {
                PrimalityTestType.Fermat => new FermatTest(),
                PrimalityTestType.SolovayStrassen => new SolovayStrassenTest(),
                PrimalityTestType.MillerRabin => new MillerRabinTest(),
                _ => throw new ArgumentException("Invalid test type")
            };
            _minProbability = minProbability;
            _bitLength = bitLength;
        }

        public (RSAPublicKey publicKey, RSAPrivateKey privateKey) GenerateKeyPair()
        {
            BigInteger p = GeneratePrime();
            BigInteger q = GeneratePrime();
            
            while (p == q)
            {
                q = GeneratePrime();
            }

            var n = p * q;
            var phi = (p - 1) * (q - 1);
            
            BigInteger e = 65537;
            if (MathService.Gcd(e, phi) != 1)
            {
                e = 3; 
                while (MathService.Gcd(e, phi) != 1)
                {
                    e += 2;
                }
            }

            var (gcd, d, _) = MathService.ExtendedGcd(e, phi);
            if (gcd != 1) throw new InvalidOperationException("Cannot find modular inverse");
            
            d = ((d % phi) + phi) % phi;

            return (new RSAPublicKey(n, e), new RSAPrivateKey(n, d, p, q));
        }

        private BigInteger GeneratePrime()
        {
            BigInteger candidate;
            do
            {
                candidate = GenerateRandomOddNumber(_bitLength);
            } while (!_primalityTest.IsPrime(candidate, _minProbability));
            return candidate;
        }

        private static BigInteger GenerateRandomOddNumber(int bitLength)
        {
            var bytes = new byte[bitLength / 8 + 1]; 
            _random.NextBytes(bytes);
            bytes[^1] = 0; 
            bytes[^2] |= 0x80; 
            bytes[0] |= 0x01; 
            return new BigInteger(bytes);
        }


    }

    private readonly KeyGenerator _keyGenerator;
    private RSAPublicKey? _publicKey;
    private RSAPrivateKey? _privateKey;

    public RSAService(PrimalityTestType testType, double minProbability, int bitLength)
    {
        _keyGenerator = new KeyGenerator(testType, minProbability, bitLength);
    }

    public void GenerateNewKeyPair()
    {
        (_publicKey, _privateKey) = _keyGenerator.GenerateKeyPair();
    }

    public BigInteger Encrypt(BigInteger message)
    {
        if (_publicKey == null) throw new InvalidOperationException("No key pair generated");
        if (message >= _publicKey.N) throw new ArgumentException("Message too large");
        
        return MathService.ModularPow(message, _publicKey.E, _publicKey.N);
    }

    public BigInteger Decrypt(BigInteger ciphertext)
    {
        if (_privateKey == null) throw new InvalidOperationException("No key pair generated");
        
        return MathService.ModularPow(ciphertext, _privateKey.D, _privateKey.N);
    }

    public RSAPublicKey? GetPublicKey() => _publicKey;
    public RSAPrivateKey? GetPrivateKey() => _privateKey;
}

public record RSAPublicKey(BigInteger N, BigInteger E);
public record RSAPrivateKey(BigInteger N, BigInteger D, BigInteger P, BigInteger Q);