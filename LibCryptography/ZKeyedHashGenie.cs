/*
    FileName: ZKeyedHashGenie.cs
    Version: 0.1
    Namespace: Omi24.Cryptography
    Description: ZKeyedHash genie.
    Web: http://www.omi24.com

    History:
        0.10: 20180522, 馮瑞祥 - Zak Fong
*/

using System;
using System.IO;
using System.Linq;

namespace Omi24.Cryptography
{
    /// <summary>
    /// ZKeyedHash genie.
    /// </summary>
    public class ZKeyedHashGenie
    {
        #region Const

        private const int KReadByteLength = 1024;

        #endregion Const

        #region Method

        /// <summary>
        /// Sign a file using keyed hash.
        /// </summary>
        /// <param name="hashType">Hash type.</param>
        /// <param name="key">Key</param>
        /// <param name="sourceFilePath">Source file path.</param>
        public static byte[] Sign(ZKeyedHashAlgorithmType hashType, byte[] key, byte[] source)
        {
            #region Check inputs.

            if (key == null)
            {
                throw new ArgumentNullException(LL.ZKeyedHashGenie_ArgumentNullException_Key);
            }
            if (source == null)
            {
                throw new ArgumentNullException(LL.ZKeyedHashGenie_ArgumentNullException_Source);
            }

            #endregion Check inputs.

            using (var hmac = new ZKeyedHash(hashType, key))
            {
                // Write hash value to signed file header.
                var hashValue = hmac.ComputeHash(inputStream);
                inputStream.Position = 0;
                outputStream.Write(hashValue, 0, hashValue.Length);

                // Write source file contents to signed file.
                int bytesRead;
                var buffer = new byte[KReadByteLength];

                do
                {
                    bytesRead = inputStream.Read(buffer, 0, KReadByteLength);
                    outputStream.Write(buffer, 0, bytesRead);
                } while (bytesRead > 0);
            }
        }

        /// <summary>
        /// Sign a file using keyed hash.
        /// </summary>
        /// <param name="hashType">Hash type.</param>
        /// <param name="key">Key</param>
        /// <param name="sourceFilePath">Source file path.</param>
        /// <param name="signedFilePath">Signed file path.</param>
        public static void Sign(ZKeyedHashAlgorithmType hashType, byte[] key, string sourceFilePath, string signedFilePath)
        {
            #region Check inputs.

            if (key == null)
            {
                throw new ArgumentNullException(LL.ZKeyedHashGenie_ArgumentNullException_Key);
            }

            if (File.Exists(sourceFilePath))
            {
                throw new FileNotFoundException(LL.ZKeyedHashGenie_FileNotFoundException_SourceFilePath);
            }

            #endregion Check inputs.

            using (var hmac = new ZKeyedHash(hashType, key))
            {
                using (var inputStream = new FileStream(sourceFilePath, FileMode.Open))
                {
                    using (var outputStream = new FileStream(signedFilePath, FileMode.Create))
                    {
                        // Write hash value to signed file header.
                        var hashValue = hmac.ComputeHash(inputStream);
                        inputStream.Position = 0;
                        outputStream.Write(hashValue, 0, hashValue.Length);

                        // Write source file contents to signed file.
                        int bytesRead;
                        var buffer = new byte[KReadByteLength];

                        do
                        {
                            bytesRead = inputStream.Read(buffer, 0, KReadByteLength);
                            outputStream.Write(buffer, 0, bytesRead);
                        } while (bytesRead > 0);
                    }
                }
            }
        }

        #region Verify

        /// <summary>
        /// Verify if the key stored in the source file matches the content hash.
        /// </summary>
        /// <param name="hashType">Hash type.</param>
        /// <param name="key">Key</param>
        /// <param name="sourceFilePath">Source file path.</param>
        /// <returns>Whether hash matches the content.</returns>
        public static bool Verify(ZKeyedHashAlgorithmType hashType, byte[] key, string sourceFilePath)
        {
            #region Check inputs.

            if (key == null)
            {
                throw new ArgumentNullException(LL.ZKeyedHashGenie_ArgumentNullException_Key);
            }
            if (File.Exists(sourceFilePath))
            {
                throw new FileNotFoundException(LL.ZKeyedHashGenie_FileNotFoundException_SourceFilePath);
            }

            #endregion Check inputs.

            using (var hmac = new ZKeyedHash(hashType, key))
            {
                var storedHash = new byte[hmac.HashSize / 8];

                using (var inputStream = new FileStream(sourceFilePath, FileMode.Open))
                {
                    inputStream.Read(storedHash, 0, storedHash.Length);

                    var computedHash = hmac.ComputeHash(inputStream);

                    if (storedHash.Where((t, i) => computedHash[i] != t).Any())
                    {
                        return false;
                    }
                }
            }

            return true;
        }

        #endregion Verify

        #endregion Method
    }
}