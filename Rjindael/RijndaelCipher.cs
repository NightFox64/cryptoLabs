using System;
using System.Linq;
using CryptoLibrary;

namespace Rijndael
{
    public class RijndaelCipher : ISymmetricCipher, IKeyExpansion, IRoundFunction
    {
        private readonly GF256Service _gf256;
        private readonly byte _modulus;
        private readonly int _blockSize;
        private readonly int _keySize;
        private readonly int _rounds;
        
        private byte[] _sBox = null!;
        private byte[] _invSBox = null!;
        private byte[][] _roundKeys = null!;

        public RijndaelCipher(int blockSize, int keySize, byte modulus)
        {
            if (blockSize != 128 && blockSize != 192 && blockSize != 256)
                throw new ArgumentException("Block size must be 128, 192, or 256 bits");
            if (keySize != 128 && keySize != 192 && keySize != 256)
                throw new ArgumentException("Key size must be 128, 192, or 256 bits");

            _blockSize = blockSize / 8;
            _keySize = keySize / 8;
            _modulus = modulus;
            _gf256 = new GF256Service();
            
            _rounds = Math.Max(_blockSize, _keySize) / 4 + 6;
            
            InitializeSBoxes();
        }

        private void InitializeSBoxes()
        {
            _sBox = new byte[256];
            _invSBox = new byte[256];

            _sBox[0] = 0x63;
            _invSBox[0x63] = 0;

            for (int i = 1; i < 256; i++)
            {
                byte inv = _gf256.Inverse((byte)i, _modulus);
                byte sVal = AffineTransform(inv);
                _sBox[i] = sVal;
                _invSBox[sVal] = (byte)i;
            }
        }

        private byte AffineTransform(byte input)
        {
            byte result = 0;
            byte temp = input;
            
            for (int i = 0; i < 8; i++)
            {
                byte bit = (byte)((temp & 1) ^ ((temp >> 4) & 1) ^ ((temp >> 5) & 1) ^ ((temp >> 6) & 1) ^ ((temp >> 7) & 1));
                result |= (byte)(bit << i);
                temp = (byte)((temp >> 1) | ((temp & 1) << 7));
            }
            
            return (byte)(result ^ 0x63);
        }

        public void SetKey(byte[] key)
        {
            if (key.Length != _keySize)
                throw new ArgumentException($"Key must be {_keySize} bytes");
            
            _roundKeys = GenerateRoundKeys(key);
        }

        public byte[][] GenerateRoundKeys(byte[] masterKey)
        {
            var keys = new byte[_rounds + 1][];
            var temp = new byte[4];
            var expandedKey = new byte[(_rounds + 1) * _blockSize];
            
            Array.Copy(masterKey, expandedKey, masterKey.Length);

            for (int i = _keySize; i < expandedKey.Length; i += 4)
            {
                Array.Copy(expandedKey, i - 4, temp, 0, 4);

                if (i % _keySize == 0)
                {
                    RotWord(temp);
                    SubWord(temp);
                    temp[0] ^= GetRcon(i / _keySize);
                }
                else if (_keySize > 24 && i % _keySize == 16)
                {
                    SubWord(temp);
                }

                for (int j = 0; j < 4; j++)
                {
                    expandedKey[i + j] = (byte)(expandedKey[i + j - _keySize] ^ temp[j]);
                }
            }

            for (int i = 0; i <= _rounds; i++)
            {
                keys[i] = new byte[_blockSize];
                Array.Copy(expandedKey, i * _blockSize, keys[i], 0, _blockSize);
            }

            return keys;
        }

        public byte[] Transform(byte[] inputBlock, byte[] roundKey)
        {
            var state = new byte[_blockSize];
            Array.Copy(inputBlock, state, _blockSize);
            
            AddRoundKey(state, roundKey);
            return state;
        }

        public byte[] Encrypt(byte[] plaintext)
        {
            if (plaintext.Length != _blockSize)
                throw new ArgumentException($"Input must be {_blockSize} bytes");

            var state = new byte[_blockSize];
            Array.Copy(plaintext, state, _blockSize);

            AddRoundKey(state, _roundKeys[0]);

            for (int round = 1; round < _rounds; round++)
            {
                SubBytes(state);
                ShiftRows(state);
                MixColumns(state);
                AddRoundKey(state, _roundKeys[round]);
            }

            SubBytes(state);
            ShiftRows(state);
            AddRoundKey(state, _roundKeys[_rounds]);

            return state;
        }

        public byte[] Decrypt(byte[] ciphertext)
        {
            if (ciphertext.Length != _blockSize)
                throw new ArgumentException($"Input must be {_blockSize} bytes");

            var state = new byte[_blockSize];
            Array.Copy(ciphertext, state, _blockSize);

            AddRoundKey(state, _roundKeys[_rounds]);

            for (int round = _rounds - 1; round > 0; round--)
            {
                InvShiftRows(state);
                InvSubBytes(state);
                AddRoundKey(state, _roundKeys[round]);
                InvMixColumns(state);
            }

            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, _roundKeys[0]);

            return state;
        }

        private void SubBytes(byte[] state)
        {
            for (int i = 0; i < state.Length; i++)
                state[i] = _sBox[state[i]];
        }

        private void InvSubBytes(byte[] state)
        {
            for (int i = 0; i < state.Length; i++)
                state[i] = _invSBox[state[i]];
        }

        private void ShiftRows(byte[] state)
        {
            int cols = _blockSize / 4;
            var temp = new byte[_blockSize];
            Array.Copy(state, temp, _blockSize);

            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < cols; col++)
                {
                    state[row * cols + col] = temp[row * cols + (col + row) % cols];
                }
            }
        }

        private void InvShiftRows(byte[] state)
        {
            int cols = _blockSize / 4;
            var temp = new byte[_blockSize];
            Array.Copy(state, temp, _blockSize);

            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < cols; col++)
                {
                    state[row * cols + col] = temp[row * cols + (col - row + cols) % cols];
                }
            }
        }

        private void MixColumns(byte[] state)
        {
            int cols = _blockSize / 4;
            for (int col = 0; col < cols; col++)
            {
                var column = new byte[4];
                for (int i = 0; i < 4; i++)
                    column[i] = state[i * cols + col];

                state[0 * cols + col] = (byte)(_gf256.Multiply(0x02, column[0], _modulus) ^ 
                                              _gf256.Multiply(0x03, column[1], _modulus) ^ 
                                              column[2] ^ column[3]);
                state[1 * cols + col] = (byte)(column[0] ^ 
                                              _gf256.Multiply(0x02, column[1], _modulus) ^ 
                                              _gf256.Multiply(0x03, column[2], _modulus) ^ 
                                              column[3]);
                state[2 * cols + col] = (byte)(column[0] ^ column[1] ^ 
                                              _gf256.Multiply(0x02, column[2], _modulus) ^ 
                                              _gf256.Multiply(0x03, column[3], _modulus));
                state[3 * cols + col] = (byte)(_gf256.Multiply(0x03, column[0], _modulus) ^ 
                                              column[1] ^ column[2] ^ 
                                              _gf256.Multiply(0x02, column[3], _modulus));
            }
        }

        private void InvMixColumns(byte[] state)
        {
            int cols = _blockSize / 4;
            for (int col = 0; col < cols; col++)
            {
                var column = new byte[4];
                for (int i = 0; i < 4; i++)
                    column[i] = state[i * cols + col];

                state[0 * cols + col] = (byte)(_gf256.Multiply(0x0E, column[0], _modulus) ^ 
                                              _gf256.Multiply(0x0B, column[1], _modulus) ^ 
                                              _gf256.Multiply(0x0D, column[2], _modulus) ^ 
                                              _gf256.Multiply(0x09, column[3], _modulus));
                state[1 * cols + col] = (byte)(_gf256.Multiply(0x09, column[0], _modulus) ^ 
                                              _gf256.Multiply(0x0E, column[1], _modulus) ^ 
                                              _gf256.Multiply(0x0B, column[2], _modulus) ^ 
                                              _gf256.Multiply(0x0D, column[3], _modulus));
                state[2 * cols + col] = (byte)(_gf256.Multiply(0x0D, column[0], _modulus) ^ 
                                              _gf256.Multiply(0x09, column[1], _modulus) ^ 
                                              _gf256.Multiply(0x0E, column[2], _modulus) ^ 
                                              _gf256.Multiply(0x0B, column[3], _modulus));
                state[3 * cols + col] = (byte)(_gf256.Multiply(0x0B, column[0], _modulus) ^ 
                                              _gf256.Multiply(0x0D, column[1], _modulus) ^ 
                                              _gf256.Multiply(0x09, column[2], _modulus) ^ 
                                              _gf256.Multiply(0x0E, column[3], _modulus));
            }
        }

        private void AddRoundKey(byte[] state, byte[] roundKey)
        {
            for (int i = 0; i < state.Length; i++)
                state[i] ^= roundKey[i];
        }

        private void RotWord(byte[] word)
        {
            byte temp = word[0];
            word[0] = word[1];
            word[1] = word[2];
            word[2] = word[3];
            word[3] = temp;
        }

        private void SubWord(byte[] word)
        {
            for (int i = 0; i < word.Length; i++)
                word[i] = _sBox[word[i]];
        }

        private byte GetRcon(int round)
        {
            return _gf256.Power(0x02, round - 1, _modulus);
        }
    }
}