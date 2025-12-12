using System;

namespace CryptoLibrary
{
    public class FeistelNetwork : ISymmetricCipher
    {
        private readonly IKeyExpansion _keyExpansion;
        private readonly IRoundFunction _roundFunction;
        private readonly int _rounds;
        private byte[][] _roundKeys = Array.Empty<byte[]>();

        public FeistelNetwork(IKeyExpansion keyExpansion, IRoundFunction roundFunction, int rounds = 16)
        {
            _keyExpansion = keyExpansion;
            _roundFunction = roundFunction;
            _rounds = rounds;
        }

        public void SetKey(byte[] key)
        {
            _roundKeys = _keyExpansion.GenerateRoundKeys(key);
        }

        public byte[] Encrypt(byte[] plaintext)
        {
            if (plaintext.Length != 8)
                throw new ArgumentException("Block size must be 8 bytes");

            byte[] left = new byte[4];
            byte[] right = new byte[4];
            Array.Copy(plaintext, 0, left, 0, 4);
            Array.Copy(plaintext, 4, right, 0, 4);

            for (int round = 0; round < _rounds; round++)
            {
                byte[] newLeft = (byte[])right.Clone();
                byte[] fResult = _roundFunction.Transform(right, _roundKeys[round]);
                
                for (int i = 0; i < 4; i++)
                {
                    left[i] ^= fResult[i];
                }
                
                right = left;
                left = newLeft;
            }

            byte[] result = new byte[8];
            Array.Copy(left, 0, result, 0, 4);
            Array.Copy(right, 0, result, 4, 4);
            return result;
        }

        public byte[] Decrypt(byte[] ciphertext)
        {
            if (ciphertext.Length != 8)
                throw new ArgumentException("Block size must be 8 bytes");

            byte[] left = new byte[4];
            byte[] right = new byte[4];
            Array.Copy(ciphertext, 0, left, 0, 4);
            Array.Copy(ciphertext, 4, right, 0, 4);

            for (int round = _rounds - 1; round >= 0; round--)
            {
                byte[] newRight = (byte[])left.Clone();
                byte[] fResult = _roundFunction.Transform(left, _roundKeys[round]);
                
                for (int i = 0; i < 4; i++)
                {
                    right[i] ^= fResult[i];
                }
                
                left = right;
                right = newRight;
            }

            byte[] result = new byte[8];
            Array.Copy(left, 0, result, 0, 4);
            Array.Copy(right, 0, result, 4, 4);
            return result;
        }
    }
}