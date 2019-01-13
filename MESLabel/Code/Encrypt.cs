using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Net.NetworkInformation;
using Microsoft.Win32;
using System.Threading;
using System.Windows.Forms;

namespace MESLabel.Code
{
    public enum EncryptionKeyEnum
    {
        KeyA,
        KeyB
    }
    public class EncryptionHelper
    {
        string encryptionKeyA = "pfe_Nova";
        string encryptionKeyB = "WorkHard";
        string md5Begin = "Hello";
        string md5End = "World";
        string encryptionKey = string.Empty;
        public EncryptionHelper()
        {
            this.InitKey();
        }
        public EncryptionHelper(EncryptionKeyEnum key)
        {
            this.InitKey(key);
        }
        private void InitKey(EncryptionKeyEnum key = EncryptionKeyEnum.KeyA)
        {
            switch (key)
            {
                case EncryptionKeyEnum.KeyA:
                    encryptionKey = encryptionKeyA;
                    break;
                case EncryptionKeyEnum.KeyB:
                    encryptionKey = encryptionKeyB;
                    break;
            }
        }

        public string EncryptString(string str)
        {
            return Encrypt(str, encryptionKey);
        }
        public string DecryptString(string str)
        {
            return Decrypt(str, encryptionKey);
        }
        public string GetMD5String(string str)
        {
            str = string.Concat(md5Begin, str, md5End);
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] fromData = Encoding.Unicode.GetBytes(str);
            byte[] targetData = md5.ComputeHash(fromData);
            string md5String = string.Empty;
            foreach (var b in targetData)
                md5String += b.ToString("x2");
            return md5String;
        }

        private string Encrypt(string str, string sKey)
        {
            DESCryptoServiceProvider des = new DESCryptoServiceProvider();
            byte[] inputByteArray = Encoding.Default.GetBytes(str);
            des.Key = ASCIIEncoding.ASCII.GetBytes(sKey);
            des.IV = ASCIIEncoding.ASCII.GetBytes(sKey);
            MemoryStream ms = new MemoryStream();
            CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write);
            cs.Write(inputByteArray, 0, inputByteArray.Length);
            cs.FlushFinalBlock();
            StringBuilder ret = new StringBuilder();
            foreach (byte b in ms.ToArray())
            {
                ret.AppendFormat("{0:X2}", b);
            }
            ret.ToString();
            return ret.ToString();
        }
        private string Decrypt(string pToDecrypt, string sKey)
        {
            DESCryptoServiceProvider des = new DESCryptoServiceProvider();
            byte[] inputByteArray = new byte[pToDecrypt.Length / 2];
            for (int x = 0; x < pToDecrypt.Length / 2; x++)
            {
                int i = (Convert.ToInt32(pToDecrypt.Substring(x * 2, 2), 16));
                inputByteArray[x] = (byte)i;
            }
            des.Key = ASCIIEncoding.ASCII.GetBytes(sKey);
            des.IV = ASCIIEncoding.ASCII.GetBytes(sKey);
            MemoryStream ms = new MemoryStream();
            CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write);
            cs.Write(inputByteArray, 0, inputByteArray.Length);
            cs.FlushFinalBlock();
            StringBuilder ret = new StringBuilder();
            return System.Text.Encoding.Default.GetString(ms.ToArray());
        }
    }

    public class ComputerInfo
    {
        public static string GetComputerInfo()
        {
            string info = string.Empty;
            string cpu = GetCPUInfo();
            string baseBoard = GetBaseBoardInfo();
            string bios = GetBIOSInfo();
            string mac = GetMACInfo();
            info = string.Concat(cpu, baseBoard, bios, mac);
            return info;
        }

        private static string GetCPUInfo()
        {
            string info = string.Empty;
            info = GetHardWareInfo("Win32_Processor", "ProcessorId");
            return info;
        }
        private static string GetBIOSInfo()
        {
            string info = string.Empty;
            info = GetHardWareInfo("Win32_BIOS", "SerialNumber");
            return info;
        }
        private static string GetBaseBoardInfo()
        {
            string info = string.Empty;
            info = GetHardWareInfo("Win32_BaseBoard", "SerialNumber");
            return info;
        }
        private static string GetMACInfo()
        {
            string info = string.Empty;
            info = GetHardWareInfo("Win32_BaseBoard", "SerialNumber");
            return info;
        }
        private static string GetHardWareInfo(string typePath, string key)
        {
            try
            {
                //ManagementClass managementClass = new ManagementClass(typePath);
                //ManagementObjectCollection mn = managementClass.GetInstances();
                //PropertyDataCollection properties = managementClass.Properties;
                //foreach (PropertyData property in properties)
                //{
                //    if (property.Name == key)
                //    {
                //        foreach (ManagementObject m in mn)
                //        {
                //            return m.Properties[property.Name].Value.ToString();
                //        }
                //    }

                //}
            }
            catch (Exception ex)
            {
                //这里写异常的处理  
            }
            return string.Empty;
        }
        private static string GetMacAddressByNetworkInformation()
        {
            string key = "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\";
            string macAddress = string.Empty;
            try
            {
                NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
                foreach (NetworkInterface adapter in nics)
                {
                    if (adapter.NetworkInterfaceType == NetworkInterfaceType.Ethernet
                        && adapter.GetPhysicalAddress().ToString().Length != 0)
                    {
                        string fRegistryKey = key + adapter.Id + "\\Connection";
                        RegistryKey rk = Registry.LocalMachine.OpenSubKey(fRegistryKey, false);
                        if (rk != null)
                        {
                            string fPnpInstanceID = rk.GetValue("PnpInstanceID", "").ToString();
                            int fMediaSubType = Convert.ToInt32(rk.GetValue("MediaSubType", 0));
                            if (fPnpInstanceID.Length > 3 &&
                                fPnpInstanceID.Substring(0, 3) == "PCI")
                            {
                                macAddress = adapter.GetPhysicalAddress().ToString();
                                for (int i = 1; i < 6; i++)
                                {
                                    macAddress = macAddress.Insert(3 * i - 1, ":");
                                }
                                break;
                            }
                        }

                    }
                }
            }
            catch (Exception ex)
            {
                //这里写异常的处理  
            }
            return macAddress;
        }
    }

    public class RegistFileHelper
    {
        public static string ComputerInfofile = "ComputerInfo.key";
        public static string RegistInfofile = "RegistInfo.key";
        public static void WriteRegistFile(string info)
        {
            WriteFile(info, RegistInfofile);
        }
        public static void WriteComputerInfoFile(string info)
        {
            WriteFile(info, ComputerInfofile);
        }
        public static string ReadRegistFile()
        {
            return ReadFile(RegistInfofile);
        }
        public static string ReadComputerInfoFile()
        {
            return ReadFile(ComputerInfofile);
        }
        public static bool ExistComputerInfofile()
        {
            return File.Exists(ComputerInfofile);
        }
        public static bool ExistRegistInfofile()
        {
            return File.Exists(RegistInfofile);
        }
        private static void WriteFile(string info, string fileName)
        {
            try
            {
                using (StreamWriter sw = new StreamWriter(fileName, false))
                {
                    sw.Write(info);
                    sw.Close();
                }
            }
            catch (Exception ex)
            {
            }
        }
        private static string ReadFile(string fileName)
        {
            string info = string.Empty;
            try
            {
                using (StreamReader sr = new StreamReader(fileName))
                {
                    info = sr.ReadToEnd();
                    sr.Close();
                }
            }
            catch (Exception ex)
            {
            }
            return info;
        }
    }

    //public partial class FormMain : Form
    //{
    //    private string encryptComputer = string.Empty;
    //    private bool isRegist = false;
    //    private const int timeCount = 30;
    //    public FormMain()
    //    {
    //        InitializeComponent();
    //        Control.CheckForIllegalCrossThreadCalls = false;
    //    }
    //    private void FormMain_Load(object sender, EventArgs e)
    //    {
    //        string computer = ComputerInfo.GetComputerInfo();
    //        encryptComputer = new EncryptionHelper().EncryptString(computer);
    //        if (CheckRegist() == true)
    //        {
    //            lbRegistInfo.Text = "已注册";
    //        }
    //        else
    //        {
    //            lbRegistInfo.Text = "待注册，运行十分钟后自动关闭";
    //            RegistFileHelper.WriteComputerInfoFile(encryptComputer);
    //            TryRunForm();
    //        }
    //    }
    //    /// <summary>
    //    /// 试运行窗口
    //    /// </summary>
    //    private void TryRunForm()
    //    {
    //        Thread threadClose = new Thread(CloseForm);
    //        threadClose.IsBackground = true;
    //        threadClose.Start();
    //    }
    //    private bool CheckRegist()
    //    {
    //        EncryptionHelper helper = new EncryptionHelper();
    //        string md5key = helper.GetMD5String(encryptComputer);
    //        return CheckRegistData(md5key);
    //    }
    //    private bool CheckRegistData(string key)
    //    {
    //        if (RegistFileHelper.ExistRegistInfofile() == false)
    //        {
    //            isRegist = false;
    //            return false;
    //        }
    //        else
    //        {
    //            string info = RegistFileHelper.ReadRegistFile();
    //            var helper = new EncryptionHelper(EncryptionKeyEnum.KeyB);
    //            string registData = helper.DecryptString(info);
    //            if (key == registData)
    //            {
    //                isRegist = true;
    //                return true;
    //            }
    //            else
    //            {
    //                isRegist = false;
    //                return false;
    //            }
    //        }
    //    }
    //    private void CloseForm()
    //    {
    //        int count = 0;
    //        while (count < timeCount && isRegist == false)
    //        {
    //            if (isRegist == true)
    //            {
    //                return;
    //            }
    //            Thread.Sleep(1 * 1000);
    //            count++;
    //        }
    //        if (isRegist == true)
    //        {
    //            return;
    //        }
    //        else
    //        {
    //            this.Close();
    //        }
    //    }

    //    private void btnRegist_Click(object sender, EventArgs e)
    //    {
    //        if (lbRegistInfo.Text == "已注册")
    //        {
    //            MessageBox.Show("已经注册～");
    //            return;
    //        }
    //        string fileName = string.Empty;
    //        OpenFileDialog openFileDialog = new OpenFileDialog();
    //        if (openFileDialog.ShowDialog() == DialogResult.OK)
    //        {
    //            fileName = openFileDialog.FileName;
    //        }
    //        else
    //        {
    //            return;
    //        }
    //        string localFileName = string.Concat(
    //            Environment.CurrentDirectory,
    //            Path.DirectorySeparatorChar,
    //            RegistFileHelper.RegistInfofile);
    //        if (fileName != localFileName)
    //            File.Copy(fileName, localFileName, true);

    //        if (CheckRegist() == true)
    //        {
    //            lbRegistInfo.Text = "已注册";
    //            MessageBox.Show("注册成功～");
    //        }
    //    }
    //}




}
