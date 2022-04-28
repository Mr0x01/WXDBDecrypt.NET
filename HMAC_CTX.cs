using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace WXDBDecrypt.NET
{
    [StructLayout(LayoutKind.Sequential)]
    public class HMAC_CTX
    {
        SHA_State ctx;
        unsigned char ipad[KEY_IOPAD_SIZE]; /*!< HMAC: inner padding */
        unsigned char opad[KEY_IOPAD_SIZE]; /*!< HMAC: outer padding */
    }
}
