/*
    FileName: ZKeyedHashAlgorithm.cs
    Version: 0.10
    Namespace: Omi24.Cryptography
    Description: Keyed hash algorithm types.
    Web: http://www.omi24.com

    History:
        0.10: 20180429, 馮瑞祥 - Zak Fong
*/

namespace Omi24.Cryptography
{
    /// <summary>
    /// Keyed hash type.
    /// </summary>
    public enum ZKeyedHashAlgorithmType
    {
        /// <summary>
        /// HMAC MD5
        /// </summary>
        HmacMd5 = 0,

        /// <summary>
        /// HMAC RIPEMD-160 (Suggest use SHA-256 or SHA-512)
        /// </summary>
        HmacRipeMd160 = 1,

        /// <summary>
        /// HMAC SHA-1
        /// </summary>
        HmacSha1 = 2,

        /// <summary>
        /// HMAC SHA-256
        /// </summary>
        HmacSha256 = 3,

        /// <summary>
        /// HMAC SHA-384
        /// </summary>
        HmacSha384 = 4,

        /// <summary>
        /// HMAC SHA-512
        /// </summary>
        HmacSha512 = 5,
    }
}