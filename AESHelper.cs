using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace WXDBDecrypt.NET
{
    public class AESHelper
    {
        /// <summary>
        /// AES解密
        /// </summary>
        /// <param name="content">密文</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">IV</param>
        /// <returns></returns>
        public static byte[] AESDecrypt(byte[] content, byte[] key, byte[] iv)
        {
            RijndaelManaged rijndaelCipher = new RijndaelManaged();
            rijndaelCipher.Mode = CipherMode.CBC;
            rijndaelCipher.Padding = PaddingMode.None;
            rijndaelCipher.KeySize = 256;
            rijndaelCipher.BlockSize = 128;
            rijndaelCipher.Key = key;
            rijndaelCipher.IV = iv;
            ICryptoTransform transform = rijndaelCipher.CreateDecryptor();
            byte[] plain_bytes = transform.TransformFinalBlock(content, 0, content.Length);
            return plain_bytes;
        }
    }
}
