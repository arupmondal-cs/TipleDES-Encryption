using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;

class TripleDESS
{
    static void Main()
    {
        try
        {

            Console.WriteLine("--------------------------------------------------------------------------");
            Console.WriteLine("|        TRIPLE DATA ENCRYPTION STANDARD (3DES) ENCRYPTION SCHEME        |");
            Console.WriteLine("--------------------------------------------------------------------------\n");

            Console.Write("\nEnter a String to generate 168-bits Key: ");
            String str = Console.ReadLine();
            string mysecurityKey = GetUniqueToken(24, str);
            string iv = GetUniqueToken(24, str);

            string opt = "y";
            while (opt == "y")
            {
                //Encryption Key   
                byte[] key = Encoding.UTF8.GetBytes(mysecurityKey);
                byte[] IV = Encoding.UTF8.GetBytes(iv);

                Console.WriteLine("\n------------------------------------");
                Console.WriteLine("|         KEY and IV VALUE         |");
                Console.WriteLine("------------------------------------\n");

                Console.WriteLine("Generated 168-bit Key (Base-64): {0}", Encoding.UTF8.GetString(key));
                Console.WriteLine("\nGenerated 168-bit Key (Hex): {0}", BitConverter.ToString(key));

                Console.WriteLine("\nIV value (Hex): {0}", BitConverter.ToString(IV));

                Console.WriteLine("\n---------------------------");
                Console.WriteLine("|         MESSAGE         |");
                Console.WriteLine("---------------------------\n");

                // Create a string to encrypt.
                Console.Write("Enter a message for encryption: ");
                string sData = Console.ReadLine();

                // Encrypt the string to an in-memory buffer.
                byte[] Data = EncryptTextToMemory(sData, key, IV);


                Console.WriteLine("\n-------------------------------------------");
                Console.WriteLine("|     ENCRYPTED and DECRYPTED MESSAGE     |");
                Console.WriteLine("-------------------------------------------\n");

                Console.WriteLine("Encrypted Message (Base-64) \n{0}", Encoding.UTF8.GetString(Data));
                Console.WriteLine("\nEncrypted Message (Hex) \n{0}", BitConverter.ToString(Data));

                // Decrypt the buffer back to a string.
                string Final = DecryptTextFromMemory(Data, key, IV);

                // Display the decrypted string to the console.
                Console.WriteLine("\nDecrypted Message \n{0}", Final);


                Console.WriteLine("\n=====================================================================\n");

                Console.Write("Do you want to play more? (y/n): ");
                opt = Console.ReadLine();
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
        }

    }

    public static byte[] EncryptTextToMemory(string Data, byte[] Key, byte[] IV)
    {
        try
        {
            // Create a MemoryStream.
            MemoryStream mStream = new MemoryStream();

            // Create a new TripleDES object.
            TripleDES tripleDESalg = TripleDES.Create();

            // Create a CryptoStream using the MemoryStream 
            // and the passed key and initialization vector (IV).
            CryptoStream cStream = new CryptoStream(mStream, tripleDESalg.CreateEncryptor(Key, IV), CryptoStreamMode.Write);

            // Convert the passed string to a byte array.
            byte[] toEncrypt = new ASCIIEncoding().GetBytes(Data);

            // Write the byte array to the crypto stream and flush it.
            cStream.Write(toEncrypt, 0, toEncrypt.Length);
            cStream.FlushFinalBlock();

            // Get an array of bytes from the 
            // MemoryStream that holds the 
            // encrypted data.
            byte[] ret = mStream.ToArray();

            // Close the streams.
            cStream.Close();
            mStream.Close();

            // Return the encrypted buffer.
            return ret;
        }
        catch (CryptographicException e)
        {
            Console.WriteLine("A Cryptographic error occurred: {0}", e.Message);
            return null;
        }

    }

    public static string DecryptTextFromMemory(byte[] Data, byte[] Key, byte[] IV)
    {
        try
        {
            // Create a new MemoryStream using the passed 
            // array of encrypted data.
            MemoryStream msDecrypt = new MemoryStream(Data);

            // Create a new TripleDES object.
            TripleDES tripleDESalg = TripleDES.Create();

            // Create a CryptoStream using the MemoryStream 
            // and the passed key and initialization vector (IV).
            CryptoStream csDecrypt = new CryptoStream(msDecrypt, tripleDESalg.CreateDecryptor(Key, IV), CryptoStreamMode.Read);

            // Create buffer to hold the decrypted data.
            byte[] fromEncrypt = new byte[Data.Length];

            // Read the decrypted data out of the crypto stream
            // and place it into the temporary buffer.
            csDecrypt.Read(fromEncrypt, 0, fromEncrypt.Length);

            //Convert the buffer into a string and return it.
            return new ASCIIEncoding().GetString(fromEncrypt);
        }
        catch (CryptographicException e)
        {
            Console.WriteLine("A Cryptographic error occurred: {0}", e.Message);
            return null;
        }
    }


    public static string GetUniqueToken(int length, string chars)
    {
        using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider())
        {
            byte[] data = new byte[length];

            // If chars.Length isn't a power of 2 then there is a bias if we simply use the modulus operator. The first characters of chars will be more probable than the last ones.
            // buffer used if we encounter an unusable random byte. We will regenerate it in this buffer
            byte[] buffer = null;

            // Maximum random number that can be used without introducing a bias
            int maxRandom = byte.MaxValue - ((byte.MaxValue + 1) % chars.Length);

            crypto.GetBytes(data);

            char[] result = new char[length];

            for (int i = 0; i < length; i++)
            {
                byte value = data[i];

                while (value > maxRandom)
                {
                    if (buffer == null)
                    {
                        buffer = new byte[1];
                    }

                    crypto.GetBytes(buffer);
                    value = buffer[0];
                }

                result[i] = chars[value % chars.Length];
            }

            return new string(result);
        }
    }
}