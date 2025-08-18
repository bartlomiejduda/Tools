using System.Text;

namespace ConsoleApp2
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("Usage:");
                Console.WriteLine("  program.exe -d inputFile outputFile   (decrypt)");
                Console.WriteLine("  program.exe -e inputFile outputFile   (encrypt)");
                return;
            }

            string mode = args[0];
            string inputFile = args[1];
            string outputFile = args[2];
            string password = "RINECNW121321IEQ1¡¡23OI567DNCEOWM!!!$%";

            try
            {
                if (mode == "-d")
                {
                    byte[] fileBytes = File.ReadAllBytes(inputFile);
                    string cipherText = Encoding.UTF8.GetString(fileBytes);
                    string decrypted = EncDec.DecryptString(cipherText, password);

                    File.WriteAllText(outputFile, decrypted, Encoding.UTF8);
                    Console.WriteLine("File decrypted and saved as " + outputFile);
                }
                else if (mode == "-e")
                {
                    string plainText = File.ReadAllText(inputFile, Encoding.UTF8);
                    string encrypted = EncDec.EncryptString(plainText, password);

                    File.WriteAllText(outputFile, encrypted, Encoding.UTF8);
                    Console.WriteLine("File encrypted and saved as " + outputFile);
                }
                else
                {
                    Console.WriteLine("Unknown parameter: " + mode);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
        }
    }
}