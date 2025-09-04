using System.Security.Cryptography;
using System.Text;

namespace ConsoleApp1
{
    public class StringEncrypt
    {
        private static byte[] keyArray = Encoding.UTF8.GetBytes("UKu52ePUBwetZ9wNX88o54dnfKRu0T1l");

        public static string EncryptData(string toEncrypt)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(toEncrypt);
            byte[] array = new RijndaelManaged
            {
                Key = keyArray,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.PKCS7
            }.CreateEncryptor().TransformFinalBlock(bytes, 0, bytes.Length);
            return Convert.ToBase64String(array, 0, array.Length);
        }

        public static string DecryptData(string toDecrypt)
        {
            byte[] array = Convert.FromBase64String(toDecrypt);
            byte[] bytes = new RijndaelManaged
            {
                Key = keyArray,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.PKCS7
            }.CreateDecryptor().TransformFinalBlock(array, 0, array.Length);
            return Encoding.UTF8.GetString(bytes);
        }
    }

}
