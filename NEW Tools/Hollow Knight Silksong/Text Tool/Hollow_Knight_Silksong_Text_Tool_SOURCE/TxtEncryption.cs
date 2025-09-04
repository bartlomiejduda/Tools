using System.Security.Cryptography;
using System.Text;

namespace ConsoleApp1
{
    public class TxtEncryption
    {
        private static byte[] key = Encoding.UTF8.GetBytes("UKu52ePUBwetZ9wNX88o54dnfKRu0T1l");

        public static string EncryptTxtData(string textToEncrypt)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(textToEncrypt);
            byte[] array = new RijndaelManaged
            {
                Key = key, Mode = CipherMode.ECB, Padding = PaddingMode.PKCS7
            }.CreateEncryptor().TransformFinalBlock(bytes, 0, bytes.Length);
            return Convert.ToBase64String(array, 0, array.Length);
        }

        public static string DecryptTxtData(string textToDecrypt)
        {
            byte[] array = Convert.FromBase64String(textToDecrypt);
            byte[] bytes = new RijndaelManaged
            {
                Key = key, Mode = CipherMode.ECB, Padding = PaddingMode.PKCS7
            }.CreateDecryptor().TransformFinalBlock(array, 0, array.Length);
            return Encoding.UTF8.GetString(bytes);
        }
    }
}
