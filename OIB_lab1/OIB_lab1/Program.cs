using System.Text;
using System.Security.Cryptography;

static class Encryptor
{
    public static string Encrypt(string plainText, out string keyBase64, out string vectorBase64)
    {
        using (DES DesAlgorithm = DES.Create())
        {
            Console.WriteLine($"Des режим шифрования : {DesAlgorithm.Mode}");
            Console.WriteLine($"Des режим заполнения: {DesAlgorithm.Padding}");
            Console.WriteLine($"Des размер ключа : {DesAlgorithm.KeySize}");
            Console.WriteLine($"Des размер блока : {DesAlgorithm.BlockSize}");

            keyBase64 = Convert.ToBase64String(DesAlgorithm.Key); // Key - ключ шифрования
            vectorBase64 = Convert.ToBase64String(DesAlgorithm.IV); // IV - вектор инициализации нужен для того чтобы шифровать и расшифровывать данные
            File.WriteAllText("encryptKey.txt", keyBase64);
            File.WriteAllText("Ivector.txt", vectorBase64);

            ICryptoTransform encryptor = DesAlgorithm.CreateEncryptor();

            byte[] encryptedData;

            // создание потоков используемого для шифрования
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    //1-используемый поток, 2 - криптографические преобразование, 3 тип доступа
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        sw.Write(plainText);
                    }
                    encryptedData = ms.ToArray();
                }
            }
            File.WriteAllText("encryptedData.txt", Convert.ToBase64String(encryptedData));
            return Convert.ToBase64String(encryptedData);
        }
    }

    public static string Decrypte(string cipherText, string keyBase64, string vectorBase64)
    {
        using (DES DesAlgorithm = DES.Create())
        {
            DesAlgorithm.Key = Convert.FromBase64String(keyBase64);
            DesAlgorithm.IV = Convert.FromBase64String(vectorBase64);

            ICryptoTransform decryptor = DesAlgorithm.CreateDecryptor();

            byte[] cipher = Convert.FromBase64String(cipherText);

            using (MemoryStream ms = new MemoryStream(cipher))
            {
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read)) // режим для чтения данных
                {
                    using (StreamReader sr = new StreamReader(cs))
                    {
                        return sr.ReadToEnd();
                    }
                }
            }
        }
    }
}
class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Введите текст который вы хотите зашифровать:");
        string message = Console.ReadLine();
        string cipherText = Encryptor.Encrypt(message, out string keyBase64, out string vectorBase64);
        Console.WriteLine("Зашифрованное сообщение: " + cipherText);
        Console.WriteLine("Ключ шифрование в виде строки: " + keyBase64);
        Console.WriteLine("Вектор инициализации (IV) в виде строки: " + vectorBase64);
        Console.WriteLine("Расшифрованное сообщение: " + Encryptor.Decrypte(cipherText, keyBase64, vectorBase64));
        Console.WriteLine("Вычесленый хэш из файла hash.txt: " + GetHash());
    }

    static string GetHash(string? input = null)
    {
        input = input ?? File.ReadAllText("hash.txt");
        SHA384 sha = new SHA384Managed();
        var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(input));
        File.WriteAllBytes("hashedInBytes.txt", hash);
        File.WriteAllText("hashedInString.txt", Convert.ToBase64String(hash));
        return Convert.ToBase64String(hash);
    }
}