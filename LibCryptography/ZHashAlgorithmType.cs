/*
    FileName: ZHashAlgorithmType.cs
    Version: 0.10
    Namespace: Omi24.Cryptography
    Description: Hash algorithm types.
    Web: http://www.omi24.com

    History:
        0.10: 20180428, 馮瑞祥 - Zak Fong
*/

namespace Omi24.Cryptography
{
    /// <summary>
    /// Hash type.
    /// </summary>
    public enum ZHashAlgorithmType
    {
        /// <summary>
        /// MD5
        /// </summary>
        Md5 = 0,

        /// <summary>
        /// RIPEMD-160 (Suggest use SHA-256 or SHA-512)
        /// </summary>
        RipeMd160 = 1,

        /// <summary>
        /// SHA-1
        /// </summary>
        Sha1 = 2,

        /// <summary>
        /// SHA-256
        /// </summary>
        Sha256 = 3,

        /// <summary>
        /// SHA-384
        /// </summary>
        Sha384 = 4,

        /// <summary>
        /// SHA-512
        /// </summary>
        Sha512 = 5,
    }
}