using System;

namespace CryptoLibrary
{
    public class DESKeyExpansion : IKeyExpansion
    {
        private static readonly int[] PC1 = {
            57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
        };

        private static readonly int[] PC2 = {
            14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
        };

        private static readonly int[] Shifts = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

        public byte[][] GenerateRoundKeys(byte[] masterKey)
        {
            if (masterKey.Length != 8)
                throw new ArgumentException("DES key must be 8 bytes");

            byte[] permutedKey = BitPermutation.PerformPermutation(masterKey, PC1, false, false);

            byte[] left = new byte[4];
            byte[] right = new byte[4];
            
            for (int i = 0; i < 28; i++)
            {
                int byteIndex = i / 8;
                int bitIndex = 7 - (i % 8);
                if ((permutedKey[byteIndex] & (1 << bitIndex)) != 0)
                {
                    int targetByte = i / 8;
                    int targetBit = 7 - (i % 8);
                    left[targetByte] |= (byte)(1 << targetBit);
                }
            }

            for (int i = 0; i < 28; i++)
            {
                int sourceIndex = i + 28;
                int byteIndex = sourceIndex / 8;
                int bitIndex = 7 - (sourceIndex % 8);
                if ((permutedKey[byteIndex] & (1 << bitIndex)) != 0)
                {
                    int targetByte = i / 8;
                    int targetBit = 7 - (i % 8);
                    right[targetByte] |= (byte)(1 << targetBit);
                }
            }

            byte[][] roundKeys = new byte[16][];

            for (int round = 0; round < 16; round++)
            {
                LeftShift28(left, Shifts[round]);
                LeftShift28(right, Shifts[round]);

                byte[] combined = new byte[7];
                
                for (int i = 0; i < 28; i++)
                {
                    int sourceByte = i / 8;
                    int sourceBit = 7 - (i % 8);
                    if ((left[sourceByte] & (1 << sourceBit)) != 0)
                    {
                        int targetByte = i / 8;
                        int targetBit = 7 - (i % 8);
                        combined[targetByte] |= (byte)(1 << targetBit);
                    }
                }

                for (int i = 0; i < 28; i++)
                {
                    int sourceByte = i / 8;
                    int sourceBit = 7 - (i % 8);
                    if ((right[sourceByte] & (1 << sourceBit)) != 0)
                    {
                        int targetIndex = i + 28;
                        int targetByte = targetIndex / 8;
                        int targetBit = 7 - (targetIndex % 8);
                        combined[targetByte] |= (byte)(1 << targetBit);
                    }
                }

                roundKeys[round] = BitPermutation.PerformPermutation(combined, PC2, false, false);
            }

            return roundKeys;
        }

        private static void LeftShift28(byte[] data, int positions)
        {
            for (int p = 0; p < positions; p++)
            {
                bool msb = (data[3] & 0x80) != 0;

                for (int i = 3; i > 0; i--)
                {
                    data[i] = (byte)((data[i] << 1) | ((data[i - 1] & 0x80) >> 7));
                }
                data[0] = (byte)(data[0] << 1);

                data[3] &= 0x0F;

                if (msb)
                    data[0] |= 0x01;
            }
        }
    }

    public class DESRoundFunction : IRoundFunction
    {
        private static readonly int[] E = {
            32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
        };

        private static readonly int[] P = {
            16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
            2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
        };

        private static readonly int[,] S1 = {
            {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
            {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
            {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
            {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
        };

        private static readonly int[,] S2 = {
            {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
            {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
            {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
            {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
        };

        private static readonly int[,] S3 = {
            {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
            {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
            {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
            {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
        };

        private static readonly int[,] S4 = {
            {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
            {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
            {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
            {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
        };

        private static readonly int[,] S5 = {
            {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
            {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
            {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
            {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
        };

        private static readonly int[,] S6 = {
            {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
            {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
            {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
            {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
        };

        private static readonly int[,] S7 = {
            {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
            {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
            {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
            {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
        };

        private static readonly int[,] S8 = {
            {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
            {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
            {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
            {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
        };

        private static readonly int[,,] SBoxes = {
            {{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
             {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
             {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
             {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},
            
            {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
             {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
             {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
             {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}},
            
            {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
             {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
             {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
             {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}},
            
            {{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
             {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
             {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
             {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}},
            
            {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
             {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
             {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
             {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}},
            
            {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
             {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
             {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
             {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}},
            
            {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
             {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
             {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
             {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}},
            
            {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
             {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
             {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
             {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}
        };

        public byte[] Transform(byte[] inputBlock, byte[] roundKey)
        {
            if (inputBlock.Length != 4)
                throw new ArgumentException("Input block must be 4 bytes");

            byte[] expanded = BitPermutation.PerformPermutation(inputBlock, E, false, false);

            for (int i = 0; i < Math.Min(expanded.Length, roundKey.Length); i++)
            {
                expanded[i] ^= roundKey[i];
            }

            byte[] sBoxOutput = new byte[4];
            for (int i = 0; i < 8; i++)
            {
                int startBit = i * 6;
                int sBoxInput = 0;

                for (int j = 0; j < 6; j++)
                {
                    int bitIndex = startBit + j;
                    int byteIndex = bitIndex / 8;
                    int bitPosition = 7 - (bitIndex % 8);
                    
                    if (byteIndex < expanded.Length && (expanded[byteIndex] & (1 << bitPosition)) != 0)
                    {
                        sBoxInput |= (1 << (5 - j));
                    }
                }

                int row = ((sBoxInput & 0x20) >> 4) | (sBoxInput & 0x01);
                int col = (sBoxInput & 0x1E) >> 1;

                int sBoxValue = SBoxes[i, row, col];

                int outputBitStart = i * 4;
                for (int j = 0; j < 4; j++)
                {
                    int bitIndex = outputBitStart + j;
                    int byteIndex = bitIndex / 8;
                    int bitPosition = 7 - (bitIndex % 8);
                    
                    if ((sBoxValue & (1 << (3 - j))) != 0)
                    {
                        sBoxOutput[byteIndex] |= (byte)(1 << bitPosition);
                    }
                }
            }

            return BitPermutation.PerformPermutation(sBoxOutput, P, false, false);
        }
    }

    public class DES : ISymmetricCipher
    {
        private static readonly int[] IP = {
            58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
        };

        private static readonly int[] FP = {
            40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
        };

        private readonly FeistelNetwork _feistelNetwork;

        public DES()
        {
            _feistelNetwork = new FeistelNetwork(new DESKeyExpansion(), new DESRoundFunction(), 16);
        }

        public void SetKey(byte[] key)
        {
            _feistelNetwork.SetKey(key);
        }

        public byte[] Encrypt(byte[] plaintext)
        {
            if (plaintext.Length != 8)
                throw new ArgumentException("DES block size must be 8 bytes");

            byte[] permuted = BitPermutation.PerformPermutation(plaintext, IP, false, false);

            byte[] encrypted = _feistelNetwork.Encrypt(permuted);

            return BitPermutation.PerformPermutation(encrypted, FP, false, false);
        }

        public byte[] Decrypt(byte[] ciphertext)
        {
            if (ciphertext.Length != 8)
                throw new ArgumentException("DES block size must be 8 bytes");

            byte[] permuted = BitPermutation.PerformPermutation(ciphertext, IP, false, false);

            byte[] decrypted = _feistelNetwork.Decrypt(permuted);

            return BitPermutation.PerformPermutation(decrypted, FP, false, false);
        }
    }
}