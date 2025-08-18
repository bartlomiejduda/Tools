using System.Text;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace ConsoleApp2
{

    public class EncDec
    {
        private static byte[] Encrypt(byte[] clearText, byte[] Key, byte[] IV)
        {
            MemoryStream memoryStream = new MemoryStream();
            Rijndael rijndael = Rijndael.Create();
            rijndael.Key = Key;
            rijndael.IV = IV;
            CryptoStream cryptoStream = new CryptoStream(memoryStream, rijndael.CreateEncryptor(), CryptoStreamMode.Write);
            cryptoStream.Write(clearText, 0, clearText.Length);
            cryptoStream.Close();
            return memoryStream.ToArray();
        }

        public static byte[] Encrypt(string clearText, string Password)
        {
            byte[] bytes = Encoding.Unicode.GetBytes(clearText);
            PasswordDeriveBytes passwordDeriveBytes = new PasswordDeriveBytes(Password, new byte[13]
            {
            73, 118, 97, 110, 32, 77, 101, 100, 118, 101,
            100, 101, 118
            });
            return Encrypt(bytes, passwordDeriveBytes.GetBytes(32), passwordDeriveBytes.GetBytes(16));
        }

        public static string EncryptString(string clearText, string Password)
        {
            return Convert.ToBase64String(Encrypt(clearText, Password));
        }

        private static byte[] Decrypt(byte[] cipherData, byte[] Key, byte[] IV)
        {
            if (cipherData.Length == 0)
            {
                return cipherData;
            }
            try
            {
                MemoryStream memoryStream = new MemoryStream();
                Rijndael rijndael = Rijndael.Create();
                rijndael.Key = Key;
                rijndael.IV = IV;
                CryptoStream cryptoStream = new CryptoStream(memoryStream, rijndael.CreateDecryptor(), CryptoStreamMode.Write);
                cryptoStream.Write(cipherData, 0, cipherData.Length);
                cryptoStream.Close();
                return memoryStream.ToArray();
            }
            catch (Exception ex)
            {
                return cipherData;
            }
        }

        public static string Decrypt(byte[] cipherBytes, string Password)
        {
            PasswordDeriveBytes passwordDeriveBytes = new PasswordDeriveBytes(Password, new byte[13]
            {
                73, 118, 97, 110, 32, 77, 101, 100, 118, 101, 100, 101, 118
            });
            byte[] bytes = Decrypt(cipherBytes, passwordDeriveBytes.GetBytes(32), passwordDeriveBytes.GetBytes(16));
            return Encoding.Unicode.GetString(bytes);
        }

        public static string DecryptString(string cipherText, string Password, bool utf8Encoding = false)
        {
            byte[] cipherBytes = ((utf8Encoding || !IsBase64String(cipherText)) ? Encoding.UTF8.GetBytes(cipherText) : Convert.FromBase64String(cipherText));
            return Decrypt(cipherBytes, Password);
        }

        public static bool IsBase64String(string s)
        {
            s = s.Trim();
            if (s.Length % 4 == 0)
            {
                return Regex.IsMatch(s, "^[a-zA-Z0-9\\+/]*={0,3}$", RegexOptions.None);
            }
            return false;
        }
    }
}
