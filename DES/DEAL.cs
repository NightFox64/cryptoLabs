using System;

namespace CryptoLibrary
{
    public class DESAdapter : IRoundFunction
    {
        private readonly DES _des = new DES();

        public byte[] Transform(byte[] inputBlock, byte[] roundKey)
        {
            if (inputBlock.Length != 8)
                throw new ArgumentException("Input block must be 8 bytes for DES");
            
            if (roundKey.Length != 8)
                throw new ArgumentException("Round key must be 8 bytes for DES");

            _des.SetKey(roundKey);
            return _des.Encrypt(inputBlock);
        }
    }

    public class DEALKeyExpansion : IKeyExpansion
    {
        public byte[][] GenerateRoundKeys(byte[] masterKey)
        {
            if (masterKey.Length != 16)
                throw new ArgumentException("DEAL master key must be 16 bytes (128 bits)");

            byte[][] roundKeys = new byte[6][];

            byte[] K1 = new byte[8];
            byte[] K2 = new byte[8];
            Array.Copy(masterKey, 0, K1, 0, 8);
            Array.Copy(masterKey, 8, K2, 0, 8);

            var des = new DES();

            for (int i = 0; i < 6; i++)
            {
                roundKeys[i] = new byte[8];
                
                if (i < 3)
                {
                    des.SetKey(K1);
                    byte[] constant = new byte[8];
                    constant[7] = (byte)(i + 1);
                    roundKeys[i] = des.Encrypt(constant);
                }
                else
                {
                    des.SetKey(K2);
                    byte[] constant = new byte[8];
                    constant[7] = (byte)(i - 2);
                    roundKeys[i] = des.Encrypt(constant);
                }
            }

            return roundKeys;
        }
    }

    public class DEALRoundFunction : IRoundFunction
    {
        private readonly DESAdapter _desAdapter = new DESAdapter();

        public byte[] Transform(byte[] inputBlock, byte[] roundKey)
        {
            if (inputBlock.Length != 4)
                throw new ArgumentException("Input block must be 4 bytes");
            
            if (roundKey.Length != 8)
                throw new ArgumentException("Round key must be 8 bytes");

            byte[] expandedBlock = new byte[8];
            Array.Copy(inputBlock, 0, expandedBlock, 0, 4);
            Array.Copy(inputBlock, 0, expandedBlock, 4, 4);
            
            byte[] result = _desAdapter.Transform(expandedBlock, roundKey);
            
            byte[] output = new byte[4];
            Array.Copy(result, 0, output, 0, 4);
            return output;
        }
    }

    public class DEAL : ISymmetricCipher
    {
        private readonly FeistelNetwork _feistelNetwork;
        private byte[][] _roundKeys = Array.Empty<byte[]>();

        public DEAL()
        {
            var keyExpansion = new DEALKeyExpansion();
            var roundFunction = new DEALRoundFunction();
            _feistelNetwork = new FeistelNetwork(keyExpansion, roundFunction, 6);
        }

        public void SetKey(byte[] key)
        {
            if (key.Length != 16)
                throw new ArgumentException("DEAL key must be 16 bytes (128 bits)");

            _feistelNetwork.SetKey(key);
        }

        public byte[] Encrypt(byte[] plaintext)
        {
            if (plaintext.Length != 8)
                throw new ArgumentException("DEAL block size must be 8 bytes");

            return _feistelNetwork.Encrypt(plaintext);
        }

        public byte[] Decrypt(byte[] ciphertext)
        {
            if (ciphertext.Length != 8)
                throw new ArgumentException("DEAL block size must be 8 bytes");

            return _feistelNetwork.Decrypt(ciphertext);
        }
    }
}