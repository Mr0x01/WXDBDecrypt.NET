using System;
using System.Collections.Generic;
using System.Text;

namespace WXDBDecrypt.NET
{
    public class SHA_State
    {
        uint32 h[5];
        unsigned char block[64];
        int blkused;
        uint32 lenhi, lenlo;
    }
}
