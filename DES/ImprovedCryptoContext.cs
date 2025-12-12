using System;
using System.IO;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace CryptoLibrary
{
    public class ImprovedCryptoContext
    {
        private readonly ISymmetricCipher _cipher;
        private readonly CipherMode _mode;
        private readonly PaddingMode _padding;
        private readonly byte[] _iv;
        private readonly object[] _additionalParams;
        private readonly int _blockSize;

        public ImprovedCryptoContext(ISymmetricCipher cipher, byte[] key, CipherMode mode, PaddingMode padding, 
            int blockSize = 8, byte[]? iv = null, params object[] additionalParams)
        {
            _cipher = cipher;
            _mode = mode;
            _padding = padding;
            _blockSize = blockSize;
            _additionalParams = additionalParams;
            
            _cipher.SetKey(key);
            
            if (iv != null)
                _iv = (byte[])iv.Clone();
            else if (RequiresIV(mode))
                _iv = GenerateRandomIV();
            else
                _iv = new byte[0];
        }

        public async Task EncryptFileAsync(string inputPath, string outputPath)
        {
            await Task.Run(() =>
            {
                byte[] data = File.ReadAllBytes(inputPath);
                byte[] encrypted = Encrypt(data);
                
                if (_padding == PaddingMode.Zeros)
                {
                    byte[] lengthBytes = BitConverter.GetBytes(data.Length);
                    byte[] result = new byte[lengthBytes.Length + encrypted.Length];
                    Array.Copy(lengthBytes, 0, result, 0, lengthBytes.Length);
                    Array.Copy(encrypted, 0, result, lengthBytes.Length, encrypted.Length);
                    File.WriteAllBytes(outputPath, result);
                }
                else
                {
                    File.WriteAllBytes(outputPath, encrypted);
                }
            });
        }

        public async Task DecryptFileAsync(string inputPath, string outputPath)
        {
            await Task.Run(() =>
            {
                byte[] data = File.ReadAllBytes(inputPath);
                byte[] decrypted;
                
                if (_padding == PaddingMode.Zeros)
                {
                    int originalLength = BitConverter.ToInt32(data, 0);
                    byte[] encryptedData = new byte[data.Length - 4];
                    Array.Copy(data, 4, encryptedData, 0, encryptedData.Length);
                    
                    byte[] fullDecrypted = Decrypt(encryptedData);
                    decrypted = new byte[originalLength];
                    Array.Copy(fullDecrypted, 0, decrypted, 0, Math.Min(originalLength, fullDecrypted.Length));
                }
                else
                {
                    decrypted = Decrypt(data);
                }
                
                File.WriteAllBytes(outputPath, decrypted);
            });
        }

        private byte[] Encrypt(byte[] plaintext)
        {
            byte[] paddedData = ApplyPadding(plaintext);
            
            return _mode switch
            {
                CipherMode.ECB => EncryptECB(paddedData),
                CipherMode.CBC => EncryptCBC(paddedData),
                CipherMode.CFB => EncryptCFB(paddedData),
                CipherMode.OFB => EncryptOFB(paddedData),
                CipherMode.CTR => EncryptCTR(paddedData),
                _ => throw new NotSupportedException($"Mode {_mode} not supported")
            };
        }

        private byte[] Decrypt(byte[] ciphertext)
        {
            byte[] decrypted = _mode switch
            {
                CipherMode.ECB => DecryptECB(ciphertext),
                CipherMode.CBC => DecryptCBC(ciphertext),
                CipherMode.CFB => DecryptCFB(ciphertext),
                CipherMode.OFB => DecryptOFB(ciphertext),
                CipherMode.CTR => DecryptCTR(ciphertext),
                _ => throw new NotSupportedException($"Mode {_mode} not supported")
            };

            return RemovePadding(decrypted);
        }

        private byte[] EncryptECB(byte[] data)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i += _blockSize)
            {
                byte[] block = new byte[_blockSize];
                Array.Copy(data, i, block, 0, _blockSize);
                byte[] encrypted = _cipher.Encrypt(block);
                Array.Copy(encrypted, 0, result, i, _blockSize);
            }
            return result;
        }

        private byte[] DecryptECB(byte[] data)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i += _blockSize)
            {
                byte[] block = new byte[_blockSize];
                Array.Copy(data, i, block, 0, _blockSize);
                byte[] decrypted = _cipher.Decrypt(block);
                Array.Copy(decrypted, 0, result, i, _blockSize);
            }
            return result;
        }

        private byte[] EncryptCBC(byte[] data)
        {
            byte[] result = new byte[data.Length];
            byte[] previousBlock = (byte[])_iv.Clone();

            for (int i = 0; i < data.Length; i += _blockSize)
            {
                byte[] block = new byte[_blockSize];
                Array.Copy(data, i, block, 0, _blockSize);
                
                XorBlocks(block, previousBlock);
                byte[] encrypted = _cipher.Encrypt(block);
                Array.Copy(encrypted, 0, result, i, _blockSize);
                previousBlock = encrypted;
            }
            return result;
        }

        private byte[] DecryptCBC(byte[] data)
        {
            byte[] result = new byte[data.Length];
            byte[] previousBlock = (byte[])_iv.Clone();

            for (int i = 0; i < data.Length; i += _blockSize)
            {
                byte[] block = new byte[_blockSize];
                Array.Copy(data, i, block, 0, _blockSize);
                
                byte[] decrypted = _cipher.Decrypt(block);
                XorBlocks(decrypted, previousBlock);
                Array.Copy(decrypted, 0, result, i, _blockSize);
                previousBlock = block;
            }
            return result;
        }

        private byte[] EncryptCFB(byte[] data)
        {
            byte[] result = new byte[data.Length];
            byte[] feedback = (byte[])_iv.Clone();

            for (int i = 0; i < data.Length; i += _blockSize)
            {
                byte[] encrypted = _cipher.Encrypt(feedback);
                byte[] block = new byte[_blockSize];
                Array.Copy(data, i, block, 0, Math.Min(_blockSize, data.Length - i));
                
                XorBlocks(block, encrypted);
                Array.Copy(block, 0, result, i, Math.Min(_blockSize, data.Length - i));
                feedback = block;
            }
            return result;
        }

        private byte[] DecryptCFB(byte[] data)
        {
            byte[] result = new byte[data.Length];
            byte[] feedback = (byte[])_iv.Clone();

            for (int i = 0; i < data.Length; i += _blockSize)
            {
                byte[] encrypted = _cipher.Encrypt(feedback);
                byte[] block = new byte[_blockSize];
                Array.Copy(data, i, block, 0, Math.Min(_blockSize, data.Length - i));
                
                feedback = (byte[])block.Clone();
                XorBlocks(block, encrypted);
                Array.Copy(block, 0, result, i, Math.Min(_blockSize, data.Length - i));
            }
            return result;
        }

        private byte[] EncryptOFB(byte[] data)
        {
            byte[] result = new byte[data.Length];
            byte[] feedback = (byte[])_iv.Clone();

            for (int i = 0; i < data.Length; i += _blockSize)
            {
                feedback = _cipher.Encrypt(feedback);
                byte[] block = new byte[_blockSize];
                Array.Copy(data, i, block, 0, Math.Min(_blockSize, data.Length - i));
                
                XorBlocks(block, feedback);
                Array.Copy(block, 0, result, i, Math.Min(_blockSize, data.Length - i));
            }
            return result;
        }

        private byte[] DecryptOFB(byte[] data)
        {
            return EncryptOFB(data);
        }

        private byte[] EncryptCTR(byte[] data)
        {
            byte[] result = new byte[data.Length];
            byte[] counter = (byte[])_iv.Clone();

            for (int i = 0; i < (data.Length + _blockSize - 1) / _blockSize; i++)
            {
                byte[] currentCounter = new byte[_blockSize];
                Array.Copy(counter, currentCounter, _blockSize);
                
                byte[] encrypted = _cipher.Encrypt(currentCounter);
                int offset = i * _blockSize;
                int length = Math.Min(_blockSize, data.Length - offset);
                
                for (int j = 0; j < length; j++)
                {
                    result[offset + j] = (byte)(data[offset + j] ^ encrypted[j]);
                }
                
                IncrementCounter(counter);
            }
            return result;
        }

        private byte[] DecryptCTR(byte[] data)
        {
            return EncryptCTR(data);
        }

        private byte[] ApplyPadding(byte[] data)
        {
            int paddingLength = _blockSize - (data.Length % _blockSize);
            if (paddingLength == _blockSize) paddingLength = 0;

            if (paddingLength == 0)
                return data;

            byte[] padded = new byte[data.Length + paddingLength];
            Array.Copy(data, padded, data.Length);

            switch (_padding)
            {
                case PaddingMode.Zeros:
                    break;
                case PaddingMode.PKCS7:
                    for (int i = data.Length; i < padded.Length; i++)
                        padded[i] = (byte)paddingLength;
                    break;
                case PaddingMode.ANSIX923:
                    padded[padded.Length - 1] = (byte)paddingLength;
                    break;
                case PaddingMode.ISO10126:
                    var rng = new Random();
                    for (int i = data.Length; i < padded.Length - 1; i++)
                        padded[i] = (byte)rng.Next(256);
                    padded[padded.Length - 1] = (byte)paddingLength;
                    break;
            }
            return padded;
        }

        private byte[] RemovePadding(byte[] data)
        {
            if (data.Length == 0) return data;

            int paddingLength = 0;
            switch (_padding)
            {
                case PaddingMode.Zeros:
                    return data;
                case PaddingMode.PKCS7:
                    paddingLength = data[data.Length - 1];
                    if (paddingLength > 0 && paddingLength <= _blockSize && paddingLength <= data.Length)
                    {
                        for (int i = data.Length - paddingLength; i < data.Length; i++)
                        {
                            if (data[i] != paddingLength)
                            {
                                return data;
                            }
                        }
                    }
                    else
                    {
                        return data;
                    }
                    break;
                case PaddingMode.ANSIX923:
                case PaddingMode.ISO10126:
                    paddingLength = data[data.Length - 1];
                    if (paddingLength <= 0 || paddingLength > _blockSize || paddingLength > data.Length)
                    {
                        return data;
                    }
                    break;
            }

            if (paddingLength > 0 && paddingLength <= _blockSize && paddingLength <= data.Length)
            {
                byte[] result = new byte[data.Length - paddingLength];
                Array.Copy(data, result, result.Length);
                return result;
            }
            return data;
        }

        private static void XorBlocks(byte[] block1, byte[] block2)
        {
            for (int i = 0; i < Math.Min(block1.Length, block2.Length); i++)
                block1[i] ^= block2[i];
        }

        private static void IncrementCounter(byte[] counter)
        {
            for (int i = counter.Length - 1; i >= 0; i--)
            {
                if (++counter[i] != 0) break;
            }
        }

        private static bool RequiresIV(CipherMode mode)
        {
            return mode != CipherMode.ECB;
        }

        private byte[] GenerateRandomIV()
        {
            byte[] iv = new byte[_blockSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv);
            }
            return iv;
        }
    }
}