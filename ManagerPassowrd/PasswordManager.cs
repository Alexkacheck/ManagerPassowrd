using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace ManagerPassowrd
{

    public class PasswordManager
    {
        private readonly List<PasswordEntry> passwordEntries = new List<PasswordEntry>();
        private const string MasterPasswordSalt = "SaltForMasterPassword";
        private const string PasswordKeySalt = "SaltForPasswordKey";
        private string masterPassword;

        public void SetMasterPassword()
        {
            try
            {
                Console.WriteLine("Введите мастер-пароль:");
                masterPassword = Console.ReadLine();

                if (string.IsNullOrWhiteSpace(masterPassword))
                {
                    Console.WriteLine("Предупреждение: Пустой пароль может быть небезопасным.");
                }

                Console.WriteLine("Мастер-пароль установлен.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Произошла ошибка при установке мастер-пароля: {ex.Message}");
            }
        }

        public void AddPasswordEntry()
        {
            try
            {
                Console.WriteLine("Введите веб-сайт:");
                string website = Console.ReadLine();

                Console.WriteLine("Введите логин:");
                string username = Console.ReadLine();

                Console.WriteLine("Введите пароль:");
                string password = Console.ReadLine();

                string encryptedPassword = EncryptPassword(password);

                PasswordEntry entry = new PasswordEntry
                {
                    Website = website,
                    Username = username,
                    EncryptedPassword = encryptedPassword
                };

                passwordEntries.Add(entry);

                Console.WriteLine("Запись добавлена.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Произошла ошибка при добавлении записи: {ex.Message}");
            }
        }

        public void ViewPasswordEntries()
        {
            try
            {
                Console.WriteLine("Список сохраненных записей:");
                foreach (var entry in passwordEntries)
                {
                    Console.WriteLine($"Веб-сайт: {entry.Website,-20} Логин: {entry.Username}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Произошла ошибка при просмотре записей: {ex.Message}");
            }
        }

        public void SearchPasswordEntries(string query)
        {
            try
            {
                var searchResults = passwordEntries
                    .Where(entry => entry.Website.IndexOf(query, StringComparison.OrdinalIgnoreCase) != -1 ||
                                    entry.Username.IndexOf(query, StringComparison.OrdinalIgnoreCase) != -1)
                    .ToList();

                if (searchResults.Any())
                {
                    Console.WriteLine("Результаты поиска:");
                    foreach (var entry in searchResults)
                    {
                        Console.WriteLine($"Веб-сайт: {entry.Website,-20} Логин: {entry.Username}");
                    }
                }
                else
                {
                    Console.WriteLine("Записей не найдено.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Произошла ошибка при поиске записей: {ex.Message}");
            }
        }

        private string EncryptPassword(string password)
        {
            try
            {
                using (AesManaged aesAlg = new AesManaged())
                {
                    Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(masterPassword, Encoding.UTF8.GetBytes(PasswordKeySalt));
                    aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
                    aesAlg.IV = key.GetBytes(aesAlg.BlockSize / 8);

                    using (ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV))
                    {
                        using (MemoryStream msEncrypt = new MemoryStream())
                        {
                            using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                            {
                                using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                                {
                                    swEncrypt.Write(password);
                                }
                            }

                            return Convert.ToBase64String(msEncrypt.ToArray());
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Произошла ошибка при шифровании пароля: {ex.Message}");
                return null;
            }
        }

        private string DecryptPassword(string encryptedPassword)
        {
            try
            {
                using (AesManaged aesAlg = new AesManaged())
                {
                    Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(masterPassword, Encoding.UTF8.GetBytes(PasswordKeySalt));
                    aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
                    aesAlg.IV = key.GetBytes(aesAlg.BlockSize / 8);

                    using (ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
                    {
                        using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(encryptedPassword)))
                        {
                            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                            {
                                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                                {
                                    return srDecrypt.ReadToEnd();
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Произошла ошибка при дешифровании пароля: {ex.Message}");
                return null;
            }
        }
    }
}
    
