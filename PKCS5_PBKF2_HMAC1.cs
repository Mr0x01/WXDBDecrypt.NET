using System;
using System.Collections.Generic;
using System.Text;

namespace WXDBDecrypt.NET
{
    public class PKCS5_PBKF2_HMAC1
    {
        public static byte[] Calc(byte[] password_bytes, byte[] salt, int iteration_count, int key_length)
        {
            int password_length = password_bytes.Length;
            int salt_length = salt.Length;
            int generated_key_length = 0;
            while (generated_key_length < key_length)
            {

            }
        }
    }
}
