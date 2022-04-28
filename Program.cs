using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace WXDBDecrypt.NET
{
    class Program
    {
        const int IV_SIZE = 16;
        const int HMAC_SHA1_SIZE = 20;
        const int KEY_SIZE = 32;
        const int AES_BLOCK_SIZE = 16;
        const int DEFAULT_ITER = 64000;
        const int DEFAULT_PAGESIZE = 4096; //4048数据 + 16IV + 20 HMAC + 12
        const string SQLITE_HEADER = "SQLite format 3";
        static void Main(string[] args)
        {
            //解密密钥
            byte[] password_bytes = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            var file_path = args[0];
            var file_info = new FileInfo(file_path);
            //数据库文件字节数组
            var db_file_bytes = File.ReadAllBytes(file_path);
            var decrypted_file_bytes = DecryptDB(db_file_bytes, password_bytes);
            if (decrypted_file_bytes == null || decrypted_file_bytes.Length == 0)
            {
                Console.WriteLine("解密后的数组为空");
            }
            else
            {
                File.WriteAllBytes($"{file_info.Directory}{Path.DirectorySeparatorChar}Decrypted_{file_info.Name}", decrypted_file_bytes.ToArray());
                Console.WriteLine($"解密完成[{file_info.Directory}{Path.DirectorySeparatorChar}Decrypted_{file_info.Name}]");
            }
            Console.ReadKey(false);
        }

        static byte[] DecryptDB(byte[] db_file_bytes, byte[] password_bytes)
        {
            //数据库头16字节是盐值
            var salt = db_file_bytes.Take(16).ToArray();
            //HMAC验证时用的盐值需要亦或0x3a
            byte[] hmac_salt = new byte[16];
            for (int i = 0; i < salt.Length; i++)
            {
                hmac_salt[i] = (byte)(salt[i] ^ 0x3a);
            }
            //计算保留段长度
            int reserved = IV_SIZE;
            reserved += HMAC_SHA1_SIZE;
            reserved = ((reserved % AES_BLOCK_SIZE) == 0) ? reserved : ((reserved / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;

            //密钥扩展，分别对应AES解密密钥和HMAC验证密钥
            byte[] key = new byte[KEY_SIZE];
            byte[] hmac_key = new byte[KEY_SIZE];
            OpenSSLInterop.PKCS5_PBKDF2_HMAC_SHA1(password_bytes, password_bytes.Length, salt, salt.Length, DEFAULT_ITER, key.Length, key);
            OpenSSLInterop.PKCS5_PBKDF2_HMAC_SHA1(key, key.Length, hmac_salt, hmac_salt.Length, 2, hmac_key.Length, hmac_key);

            int page_no = 0;
            int offset = 16;
            Console.WriteLine("开始解密...");
            var hmac_sha1 = HMAC.Create("HMACSHA1");
            hmac_sha1.Key = hmac_key;
            ConcurrentQueue<byte> decrypted_file_bytes = new ConcurrentQueue<byte>();
            while (page_no < db_file_bytes.Length / DEFAULT_PAGESIZE)
            {
                byte[] decryped_page_bytes = new byte[DEFAULT_PAGESIZE];
                byte[] going_to_hashed = new byte[DEFAULT_PAGESIZE - reserved - offset + IV_SIZE + 4];
                db_file_bytes.Skip((page_no * DEFAULT_PAGESIZE) + offset).Take(DEFAULT_PAGESIZE - reserved - offset + IV_SIZE).ToArray().CopyTo(going_to_hashed, 0);
                var page_bytes = BitConverter.GetBytes(page_no + 1);
                page_bytes.CopyTo(going_to_hashed, DEFAULT_PAGESIZE - reserved - offset + IV_SIZE);
                //计算分页的Hash
                var hash_mac_compute = hmac_sha1.ComputeHash(going_to_hashed, 0, going_to_hashed.Count());
                //取出分页中存储的Hash
                var hash_mac_cached = db_file_bytes.Skip((page_no * DEFAULT_PAGESIZE) + DEFAULT_PAGESIZE - reserved + IV_SIZE).Take(hash_mac_compute.Length).ToArray();
                //对比两个Hash
                if (!hash_mac_compute.SequenceEqual(hash_mac_cached))
                {
                    Console.WriteLine("Hash错误...");
                    return decrypted_file_bytes.ToArray();
                }
                else
                {
                    Console.WriteLine($"解密第[{page_no + 1}]页");
                    if (page_no == 0)
                    {
                        var header_bytes = Encoding.ASCII.GetBytes(SQLITE_HEADER);
                        header_bytes.CopyTo(decryped_page_bytes, 0);
                    }
                    var encrypted_content = db_file_bytes.Skip((page_no * DEFAULT_PAGESIZE) + offset).Take(DEFAULT_PAGESIZE - reserved - offset).ToArray();
                    var iv = db_file_bytes.Skip((page_no * DEFAULT_PAGESIZE) + (DEFAULT_PAGESIZE - reserved)).Take(16).ToArray();
                    var decrypted_content = AESHelper.AESDecrypt(encrypted_content, key, iv);
                    decrypted_content.CopyTo(decryped_page_bytes, offset);
                    var reserved_bytes = db_file_bytes.Skip((page_no * DEFAULT_PAGESIZE) + DEFAULT_PAGESIZE - reserved).Take(reserved).ToArray();
                    reserved_bytes.CopyTo(decryped_page_bytes, DEFAULT_PAGESIZE - reserved);
                }
                page_no++;
                offset = 0;
                foreach (var item in decryped_page_bytes)
                {
                    decrypted_file_bytes.Enqueue(item);
                }
            }
            return decrypted_file_bytes.ToArray();
        }
    }
}
