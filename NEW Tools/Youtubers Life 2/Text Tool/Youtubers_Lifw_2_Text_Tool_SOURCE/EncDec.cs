using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace ConsoleApp2
{


    public class EncDec
    {
        public static string password_rand = "";

        public static string password_stored = "You%&3/Pirate!)()!Go¿7?Home{]++I'm%&WatchingUU";

        public static string password_stored2 = "To%67tax1231235·%&/·$%4llyR1xw t2981b 9andomStrin98398 ynw892ry3g";

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

        public static string CheckSum(string data)
        {
            string text = "";
            using MD5 mD = MD5.Create();
            return BitConverter.ToString(mD.ComputeHash(Encoding.UTF8.GetBytes(data))).Replace("-", string.Empty);
        }

        public static string CleanEncrypt(string clearText, string Password)
        {
            string input = EncryptString(clearText, Password).ToLower();
            input = new Regex("[^a-z]").Replace(input, "");
            if (input.Length > 20)
            {
                input = input.Substring(0, 20);
            }
            return input;
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
            73, 118, 97, 110, 32, 77, 101, 100, 118, 101,
            100, 101, 118
            });
            byte[] bytes = Decrypt(cipherBytes, passwordDeriveBytes.GetBytes(32), passwordDeriveBytes.GetBytes(16));
            return Encoding.Unicode.GetString(bytes);
        }

        public static string DecryptString(string cipherText, string Password, bool utf8Encoding = false)
        {
            byte[] cipherBytes = ((utf8Encoding || !IsBase64String(cipherText)) ? Encoding.UTF8.GetBytes(cipherText) : Convert.FromBase64String(cipherText));
            return Decrypt(cipherBytes, Password);
        }

        public static bool isWorldChainCorrect(string cipherText, int world_number, string Password, string deviceID)
        {
            if (cipherText == "")
            {
                return false;
            }
            if (DecryptString(cipherText, Password).Equals(deviceID + "-" + world_number))
            {
                return true;
            }
            return false;
        }

        public static string getWorldChain(int world_number, string Password, string deviceID)
        {
            return EncryptString(deviceID + "-" + world_number, Password);
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
