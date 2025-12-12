using System;
using System.IO;
using System.Security.Cryptography;
using CryptoLibrary;
using CipherMode = CryptoLibrary.CipherMode;
using PaddingMode = CryptoLibrary.PaddingMode;

namespace Rijndael
{
    public class CipherModeService
    {
        private readonly RijndaelCipher _cipher;
        private readonly int _blockSize;

        public CipherModeService(RijndaelCipher cipher, int blockSize)
        {
            _cipher = cipher;
            _blockSize = blockSize / 8;
        }

        public byte[] Encrypt(byte[] data, CipherMode mode, PaddingMode padding, byte[]? iv = null)
        {
            var paddedData = ApplyPadding(data, padding);
            
            return mode switch
            {
                CipherMode.ECB => EncryptECB(paddedData),
                CipherMode.CBC => EncryptCBC(paddedData, iv ?? GenerateIV()),
                CipherMode.CFB => EncryptCFB(data, iv ?? GenerateIV()),
                CipherMode.OFB => EncryptOFB(data, iv ?? GenerateIV()),
                CipherMode.CTR => EncryptCTR(data, iv ?? GenerateIV()),
                _ => throw new NotSupportedException($"Mode {mode} not supported")
            };
        }

        public byte[] Decrypt(byte[] data, CipherMode mode, PaddingMode padding, byte[]? iv = null)
        {
            var decrypted = mode switch
            {
                CipherMode.ECB => DecryptECB(data),
                CipherMode.CBC => DecryptCBC(data, iv ?? throw new ArgumentException("IV required for CBC")),
                CipherMode.CFB => DecryptCFB(data, iv ?? throw new ArgumentException("IV required for CFB")),
                CipherMode.OFB => DecryptOFB(data, iv ?? throw new ArgumentException("IV required for OFB")),
                CipherMode.CTR => DecryptCTR(data, iv ?? throw new ArgumentException("IV required for CTR")),
                _ => throw new NotSupportedException($"Mode {mode} not supported")
            };

            return mode == CipherMode.CFB || mode == CipherMode.OFB || mode == CipherMode.CTR 
                ? decrypted 
                : RemovePadding(decrypted, padding);
        }

        private byte[] EncryptECB(byte[] data)
        {
            var result = new byte[data.Length];
            for (int i = 0; i < data.Length; i += _blockSize)
            {
                var block = new byte[_blockSize];
                Array.Copy(data, i, block, 0, _blockSize);
                var encrypted = _cipher.Encrypt(block);
                Array.Copy(encrypted, 0, result, i, _blockSize);
            }
            return result;
        }

        private byte[] DecryptECB(byte[] data)
        {
            var result = new byte[data.Length];
            for (int i = 0; i < data.Length; i += _blockSize)
            {
                var block = new byte[_blockSize];
                Array.Copy(data, i, block, 0, _blockSize);
                var decrypted = _cipher.Decrypt(block);
                Array.Copy(decrypted, 0, result, i, _blockSize);
            }
            return result;
        }

        private byte[] EncryptCBC(byte[] data, byte[] iv)
        {
            var result = new byte[data.Length];
            var previousBlock = iv;

            for (int i = 0; i < data.Length; i += _blockSize)
            {
                var block = new byte[_blockSize];
                Array.Copy(data, i, block, 0, _blockSize);
                
                for (int j = 0; j < _blockSize; j++)
                    block[j] ^= previousBlock[j];

                var encrypted = _cipher.Encrypt(block);
                Array.Copy(encrypted, 0, result, i, _blockSize);
                previousBlock = encrypted;
            }
            return result;
        }

        private byte[] DecryptCBC(byte[] data, byte[] iv)
        {
            var result = new byte[data.Length];
            var previousBlock = iv;

            for (int i = 0; i < data.Length; i += _blockSize)
            {
                var block = new byte[_blockSize];
                Array.Copy(data, i, block, 0, _blockSize);
                
                var decrypted = _cipher.Decrypt(block);
                
                for (int j = 0; j < _blockSize; j++)
                    decrypted[j] ^= previousBlock[j];

                Array.Copy(decrypted, 0, result, i, _blockSize);
                previousBlock = block;
            }
            return result;
        }

        private byte[] EncryptCFB(byte[] data, byte[] iv)
        {
            var result = new byte[data.Length];
            var feedback = new byte[_blockSize];
            Array.Copy(iv, feedback, _blockSize);

            for (int i = 0; i < data.Length; i += _blockSize)
            {
                var keystream = _cipher.Encrypt(feedback);
                int blockLength = Math.Min(_blockSize, data.Length - i);
                
                for (int j = 0; j < blockLength; j++)
                {
                    result[i + j] = (byte)(data[i + j] ^ keystream[j]);
                }

                Array.Copy(result, i, feedback, 0, Math.Min(_blockSize, blockLength));
            }
            return result;
        }

        private byte[] DecryptCFB(byte[] data, byte[] iv)
        {
            var result = new byte[data.Length];
            var feedback = new byte[_blockSize];
            Array.Copy(iv, feedback, _blockSize);

            for (int i = 0; i < data.Length; i += _blockSize)
            {
                var keystream = _cipher.Encrypt(feedback);
                int blockLength = Math.Min(_blockSize, data.Length - i);
                
                for (int j = 0; j < blockLength; j++)
                {
                    result[i + j] = (byte)(data[i + j] ^ keystream[j]);
                }

                Array.Copy(data, i, feedback, 0, Math.Min(_blockSize, blockLength));
            }
            return result;
        }

        private byte[] EncryptOFB(byte[] data, byte[] iv)
        {
            var result = new byte[data.Length];
            var feedback = new byte[_blockSize];
            Array.Copy(iv, feedback, _blockSize);

            for (int i = 0; i < data.Length; i += _blockSize)
            {
                feedback = _cipher.Encrypt(feedback);
                int blockLength = Math.Min(_blockSize, data.Length - i);
                
                for (int j = 0; j < blockLength; j++)
                {
                    result[i + j] = (byte)(data[i + j] ^ feedback[j]);
                }
            }
            return result;
        }

        private byte[] DecryptOFB(byte[] data, byte[] iv) => EncryptOFB(data, iv);

        private byte[] EncryptCTR(byte[] data, byte[] nonce)
        {
            var result = new byte[data.Length];
            var counter = new byte[_blockSize];
            Array.Copy(nonce, counter, Math.Min(nonce.Length, _blockSize));

            for (int i = 0; i < data.Length; i += _blockSize)
            {
                var keystream = _cipher.Encrypt(counter);
                int blockLength = Math.Min(_blockSize, data.Length - i);
                
                for (int j = 0; j < blockLength; j++)
                {
                    result[i + j] = (byte)(data[i + j] ^ keystream[j]);
                }

                IncrementCounter(counter);
            }
            return result;
        }

        private byte[] DecryptCTR(byte[] data, byte[] nonce) => EncryptCTR(data, nonce);

        private byte[] ApplyPadding(byte[] data, PaddingMode padding)
        {
            int paddingLength = _blockSize - (data.Length % _blockSize);
            if (paddingLength == _blockSize) paddingLength = 0;

            var result = new byte[data.Length + paddingLength];
            Array.Copy(data, result, data.Length);

            switch (padding)
            {
                case PaddingMode.Zeros:
                    break;
                case PaddingMode.PKCS7:
                    for (int i = data.Length; i < result.Length; i++)
                        result[i] = (byte)paddingLength;
                    break;
                case PaddingMode.ANSIX923:
                    if (paddingLength > 0)
                        result[result.Length - 1] = (byte)paddingLength;
                    break;
                case PaddingMode.ISO10126:
                    var rng = RandomNumberGenerator.Create();
                    if (paddingLength > 0)
                    {
                        var randomBytes = new byte[paddingLength - 1];
                        rng.GetBytes(randomBytes);
                        Array.Copy(randomBytes, 0, result, data.Length, paddingLength - 1);
                        result[result.Length - 1] = (byte)paddingLength;
                    }
                    break;
            }

            return result;
        }

        private byte[] RemovePadding(byte[] data, PaddingMode padding)
        {
            if (data.Length == 0) return data;

            int paddingLength = padding switch
            {
                PaddingMode.Zeros => GetZerosPaddingLength(data),
                PaddingMode.PKCS7 => ValidatePKCS7Padding(data),
                PaddingMode.ANSIX923 or PaddingMode.ISO10126 => data[data.Length - 1],
                _ => 0
            };

            if (paddingLength <= 0 || paddingLength > _blockSize || paddingLength > data.Length)
                return data;

            var result = new byte[data.Length - paddingLength];
            Array.Copy(data, result, result.Length);
            return result;
        }

        private int ValidatePKCS7Padding(byte[] data)
        {
            if (data.Length == 0) return 0;
            
            byte paddingLength = data[data.Length - 1];
            if (paddingLength == 0 || paddingLength > _blockSize) return 0;
            
            for (int i = data.Length - paddingLength; i < data.Length; i++)
            {
                if (data[i] != paddingLength) return 0;
            }
            
            return paddingLength;
        }

        private int GetZerosPaddingLength(byte[] data)
        {
            int length = 0;
            for (int i = data.Length - 1; i >= 0 && data[i] == 0; i--)
                length++;
            return Math.Min(length, _blockSize - 1);
        }

        private void IncrementCounter(byte[] counter)
        {
            for (int i = counter.Length - 1; i >= 0; i--)
            {
                if (++counter[i] != 0) break;
            }
        }

        private byte[] GenerateIV()
        {
            var iv = new byte[_blockSize];
            RandomNumberGenerator.Create().GetBytes(iv);
            return iv;
        }
    }
}