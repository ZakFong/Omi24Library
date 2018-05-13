/*
    FileName: ZKeyedHash.cs
    Version: 0.11
    Namespace: Omi24.Cryptography
    Description: Keyed hash for designated algorithm.
    Web: http://www.omi24.com

    History:
        0.10: 20180429, 馮瑞祥 - Zak Fong
        0.11: 20180513, 馮瑞祥 - Zak Fong
            Move "Hash" from property to field and rename as "_hash" (No need to reveal it).
*/

using System;
using System.Security.Cryptography;
using System.Text;

namespace Omi24.Cryptography
{
    /// <inheritdoc />
    /// <summary>
    /// Keyed hash for designated algorithm.
    /// </summary>
    public class ZKeyedHash : IDisposable
    {
        #region Constructor

        /// <summary>
        /// Constructor using HMAC SHA-512.
        /// </summary>
        public ZKeyedHash()
        {
            SetHashAlgorithm(ZKeyedHashAlgorithmType.HmacSha512);
        }

        /// <summary>
        /// Constructor using designated keyed hash algorithm.
        /// </summary>
        /// <param name="hashAlgorithmType">Designated keyed hash algorithm type.</param>
        public ZKeyedHash(ZKeyedHashAlgorithmType hashAlgorithmType)
        {
            SetHashAlgorithm(hashAlgorithmType);
        }

        /// <summary>
        /// Constructor using designated keyed hash algorithm and assigned origin byte array.
        /// </summary>
        /// <param name="hashAlgorithmType">Designated keyed hash algorithm type.</param>
        /// <param name="originBytes">Origin byte array.</param>
        public ZKeyedHash(ZKeyedHashAlgorithmType hashAlgorithmType, byte[] originBytes)
        {
            OriginBytes = originBytes;

            SetHashAlgorithm(hashAlgorithmType);
        }

        /// <summary>
        /// Constructor using designated hash algorithm and assigned origin byte array.
        /// </summary>
        /// <param name="hashAlgorithmType">Designated hash algorithm type.</param>
        /// <param name="originBytes">Origin byte array.</param>
        /// <param name="saltBytes">Salt byte array.</param>
        public ZKeyedHash(ZKeyedHashAlgorithmType hashAlgorithmType, byte[] originBytes, byte[] saltBytes)
        {
            OriginBytes = originBytes;
            Salt = saltBytes;

            SetHashAlgorithm(hashAlgorithmType);
        }

        /// <summary>
        /// Constructor using designated hash algorithm and assigned origin string.
        /// </summary>
        /// <param name="hashAlgorithmType">Designated hash algorithm type.</param>
        /// <param name="originString">Origin string.</param>
        public ZKeyedHash(ZKeyedHashAlgorithmType hashAlgorithmType, string originString)
        {
            OriginString = originString;

            SetHashAlgorithm(hashAlgorithmType);
        }

        /// <summary>
        /// Constructor using designated hash algorithm and assigned origin string with salt string.
        /// </summary>
        /// <param name="hashAlgorithmType">Designated hash algorithm type.</param>
        /// <param name="originString">Origin string.</param>
        /// <param name="saltString">Salt string.</param>
        public ZKeyedHash(ZKeyedHashAlgorithmType hashAlgorithmType, string originString, string saltString)
        {
            OriginString = originString;
            SaltString = saltString;

            SetHashAlgorithm(hashAlgorithmType);
        }

        #endregion Constructor

        #region Field

        #region Hash: Hash algorithm provider.

        /// <summary>
        /// Hash algorithm provider.
        /// </summary>
        private HashAlgorithm _hash;

        #endregion Hash: Hash algorithm provider.

        #endregion Field

        #region Property

        #region HashAlgorithmType: Desinated hash algorithm type.

        /// <summary>
        /// Desinated hash algorithm.
        /// </summary>
        public ZKeyedHashAlgorithmType HashAlgorithmType { get; private set; }

        #endregion HashAlgorithmType: Desinated hash algorithm type.

        #region HashedBase64String: Hash result string in Base64 format.

        /// <summary>
        /// Hash result string in Base64 format.
        /// </summary>
        public string HashedBase64String => Convert.ToBase64String(HashedBytes);

        #endregion HashedBase64String: Hash result string in Base64 format.

        #region HashedBytes: Hash result bytes.

        /// <summary>
        /// Hash result bytes.
        /// </summary>
        public byte[] HashedBytes { get; private set; }

        #endregion HashedBytes: Hash result bytes.

        #region OriginBytes: Origin byte array.

        /// <summary>
        /// Origin byte array.
        /// </summary>
        private byte[] _originBytes;

        /// <summary>
        /// Origin byte array.
        /// </summary>
        public byte[] OriginBytes
        {
            get => _originBytes;
            set => _originBytes = value ?? throw new ArgumentNullException(LL.ZKeyedHash_ArgumentNullException_OriginBytes);
        }

        #endregion OriginBytes: Origin byte array.

        #region OriginString: Origin string.

        /// <summary>
        /// Origin string.
        /// </summary>
        public string OriginString
        {
            get => Encoding.UTF8.GetString(_originBytes);
            set => _originBytes = Encoding.UTF8.GetBytes(value ?? throw new ArgumentNullException(LL.ZKeyedHash_ArgumentNullException_OriginString));
        }

        #endregion OriginString: Origin string.

        #region SaltEnabled: Salt enabled or not.

        /// <summary>
        /// Salt enabled or not.
        /// </summary>
        public bool SaltEnabled => !(Salt == null || Salt.Length == 0);

        #endregion SaltEnabled: Salt enabled or not.

        #region Salt: Salt

        /// <summary>
        /// Salt
        /// </summary>
        public byte[] Salt { get; set; }

        #endregion Salt: Salt

        #region SaltString: Salt string.

        /// <summary>
        /// Salt string.
        /// </summary>
        public string SaltString
        {
            get => Encoding.UTF8.GetString(Salt);
            set => Salt = Encoding.UTF8.GetBytes(value ?? throw new ArgumentNullException(LL.ZKeyedHash_ArgumentNullException_SaltString));
        }

        #endregion SaltString: Salt string.

        #endregion Property

        #region Function

        #region Reset: Reset.

        /// <summary>
        /// Reset.
        /// </summary>
        public void Reset()
        {
            OriginBytes = HashedBytes = Salt = null;

            SetHashAlgorithm();
        }

        #endregion Reset: Reset.

        #region SetHashAlgorithm: Set hash algorithm. (Default: SHA-512)

        /// <summary>
        /// Set hash algorithm. (Default: SHA-512)
        /// </summary>
        private void SetHashAlgorithm()
        {
            if (_hash != null)
            {
                _hash.Dispose();
                _hash = null;
            }

            switch (HashAlgorithmType)
            {
                case ZKeyedHashAlgorithmType.HmacMd5:
                    _hash = new HMACMD5();
                    break;

                case ZKeyedHashAlgorithmType.HmacRipeMd160:
                    _hash = new HMACRIPEMD160();
                    break;

                case ZKeyedHashAlgorithmType.HmacSha1:
                    _hash = new HMACSHA1();
                    break;

                case ZKeyedHashAlgorithmType.HmacSha256:
                    _hash = new HMACSHA256();
                    break;

                case ZKeyedHashAlgorithmType.HmacSha384:
                    _hash = new HMACSHA384();
                    break;

                case ZKeyedHashAlgorithmType.HmacSha512:
                    _hash = new HMACSHA512();
                    break;

                default:
                    HashAlgorithmType = ZKeyedHashAlgorithmType.HmacSha512;
                    _hash = new HMACSHA512();
                    break;
            }
        }

        /// <summary>
        /// Set designated hash algorithm.
        /// </summary>
        /// <param name="hashAlgorithmType">Designated hash algorithm.</param>
        private void SetHashAlgorithm(ZKeyedHashAlgorithmType hashAlgorithmType)
        {
            HashAlgorithmType = hashAlgorithmType;
            SetHashAlgorithm();
        }

        #endregion SetHashAlgorithm: Set hash algorithm. (Default: SHA-512)

        #endregion Function

        #region Method

        #region ComputeHash

        /// <summary>
        /// Compute hash and return as byte array.
        /// </summary>
        /// <returns>Hashed byte array.</returns>
        public byte[] ComputeHash()
        {
            if (OriginBytes == null || OriginBytes.Length == 0)
            {
                throw new ArgumentNullException(LL.ZKeyedHash_ArgumentNullException_OriginBytes);
            }

            byte[] sourceBytes;

            if (SaltEnabled)
            {
                sourceBytes = new byte[OriginBytes.Length + Salt.Length];
                Buffer.BlockCopy(OriginBytes, 0, sourceBytes, 0, OriginBytes.Length);
                Buffer.BlockCopy(Salt, 0, sourceBytes, OriginBytes.Length, Salt.Length);
            }
            else
            {
                sourceBytes = OriginBytes;
            }

            HashedBytes = _hash.ComputeHash(sourceBytes);

            return HashedBytes;
        }

        /// <summary>
        /// Compute hash using desinated origin byte array, and return as byte array.
        /// </summary>
        /// <param name="originBytes">Origin byte array.</param>
        /// <returns>Hashed byte array.</returns>
        public byte[] ComputeHash(byte[] originBytes)
        {
            OriginBytes = originBytes;

            return ComputeHash();
        }

        /// <summary>
        /// Compute hash using desinated origin byte array and salt, finally return as byte array.
        /// </summary>
        /// <param name="originBytes">Origin byte array.</param>
        /// <param name="saltBytes">Salt byte array.</param>
        /// <returns>Hashed byte array.</returns>
        public byte[] ComputeHash(byte[] originBytes, byte[] saltBytes)
        {
            OriginBytes = originBytes;
            Salt = saltBytes;

            return ComputeHash();
        }

        /// <summary>
        /// Compute hash and return result as Base64 string.
        /// </summary>
        /// <param name="originString">Origin string.</param>
        /// <returns>Hashed Base64 string.</returns>
        public string ComputeHash(string originString)
        {
            OriginString = originString;
            ComputeHash();

            return HashedBase64String;
        }

        /// <summary>
        /// Compute hash with origin string and salt string, and return result as Base64 string.
        /// </summary>
        /// <param name="originString">Origin string.</param>
        /// <param name="saltString">Salt string.</param>
        /// <returns>Hashed Base64 string.</returns>
        public string ComputeHash(string originString, string saltString)
        {
            SaltString = saltString;

            return ComputeHash(originString);
        }

        #endregion ComputeHash

        #region CreateSalt: Using securely randomizer to generate salt.

        /// <summary>
        /// Using securely randomizer to generate salt.
        /// </summary>
        /// <param name="length">Salt length.</param>
        /// <return>Salt byte array.</return>
        public byte[] CreateSalt(int length)
        {
            Salt = new byte[length];

            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(Salt);
            }

            return Salt;
        }

        #endregion CreateSalt: Using securely randomizer to generate salt.

        #region Dispose

        /// <inheritdoc />
        /// <summary>
        /// Dispose
        /// </summary>
        void IDisposable.Dispose() => _hash?.Dispose();

        #endregion Dispose

        #endregion Method
    }
}