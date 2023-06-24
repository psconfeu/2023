using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management.Automation;
using System.IO;
using System.Collections.ObjectModel;
using System.Security;
using System.Security.Cryptography;
using System.Net;
using System.Data.SQLite;
using System.Management.Automation.Host;

namespace PSHost_with_Secrets
{
    internal class Program
    {
        public static bool VerboseOutput = false;
        static void Main(string[] args)
        {
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("Secret-Enabled PowerShell Host initialized...");
            Console.ResetColor();
            if (args.Length == 0) 
            {
                Console.Error.WriteLine("No arguments submitted");
                return;
            }
            string scriptPath = null;
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i].ToLower() == "-verbose") { VerboseOutput = true;  }
                if (args[i].ToLower() == "-file") 
                { 
                    if (i < (args.Length - 1)) {
                        if ((args[i + 1].ToLower() != "-verbose") && (args[i + 1].ToLower() != "-file"))
                        {
                            scriptPath = args[i + 1];
                            i++;
                        }
                    }
                }
            }
            if (scriptPath == null)
            {
                Console.Error.WriteLine("No file name submitted");
                return;
            }
            if (!System.IO.File.Exists(scriptPath)) {
                Console.Error.WriteLine(("Script not found: " + scriptPath));
                return;
            }

            bool scriptValid = ValidateScriptFile(scriptPath);
            Collection<PSObject> result = new Collection<PSObject>();
            if (scriptValid)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Script valid");
                Console.ResetColor();
                
                string scriptText = File.ReadAllText(scriptPath);
                PowerShell psHost = PowerShell.Create();
                if (VerboseOutput) { Console.WriteLine(("PS Instance initialised: " + psHost.InstanceId.ToString())); }
                PSCredential scriptCred = RetrieveCredential(scriptPath);
                if (null != scriptCred)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine(("Retrieved credential: " + scriptCred.UserName));
                    Console.ResetColor();
                    result = psHost.AddScript(scriptText).AddParameter("Credential", scriptCred).Invoke();
                }
                else 
                {
                    if (VerboseOutput) Console.WriteLine("No credential retrieved, running without credential");
                    result = psHost.AddScript(scriptText).Invoke();
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Script not valid");
                Console.ResetColor();
            }
            Console.WriteLine("SCRIPT OUTPUT:");
            Console.WriteLine("");
            foreach (var entry in result)
            {
                Console.WriteLine(entry.ToString());
            }
            Console.WriteLine();

            return;
        }
    
        static bool ValidateScriptFile(string FilePath)
        {
            if (!System.IO.File.Exists(FilePath))
            {
                Console.Error.WriteLine(("[SEPH] Script not found: " + FilePath));
                return false;
            }
            string dataFile = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) + "\\Data\\SEPH.sqlite";
            if (!System.IO.File.Exists(dataFile))
            {
                Console.Error.WriteLine(("[SEPH] Vault database not found: " + dataFile));
                return false;
            }
            bool res = false;
            bool ScriptExamine = false;
            string ScriptHash = null;
            bool ScriptAllowUnsigned = false;
            bool ScriptAllowBroken = false;
            SQLiteConnection dbConn = new SQLiteConnection("Data Source=" + dataFile + "; Version=3; Read Only=True;");
            dbConn.Open();
            SQLiteCommand dbCmd = dbConn.CreateCommand();
            string scriptName = Path.GetFileNameWithoutExtension(FilePath);
            dbCmd.CommandText = String.Format("SELECT * FROM SCRIPTS WHERE NAME='{0}'", (scriptName.Replace("'","''")));
            SQLiteDataReader dbRdr = dbCmd.ExecuteReader();
            if (dbRdr.HasRows)
            {
                if (VerboseOutput) { Console.WriteLine("Script found in the vault, will examine hash and signature."); }
                ScriptExamine = true;
                dbRdr.Read();
                ScriptHash = dbRdr["Hash"].ToString().ToUpper();
                if (VerboseOutput) { Console.WriteLine(("Script must have MD5 hash: " + ScriptHash)); }
                ScriptAllowUnsigned = (dbRdr["AllowMissingSignature"].ToString() == "1");
                if (VerboseOutput)
                {
                    if (ScriptAllowUnsigned)
                    {
                        Console.WriteLine("Signature will not be validated");
                    }
                    else
                    {
                        Console.WriteLine("Signature must be present");
                    }
                }
                ScriptAllowBroken = (dbRdr["AllowBrokenSignature"].ToString() == "1");
                if (VerboseOutput && !ScriptAllowUnsigned)
                {
                    if (ScriptAllowBroken)
                    {
                        Console.WriteLine("A broken signature will be tolerated");
                    }
                    else
                    {
                        Console.WriteLine("Signature must be valid");
                    }
                }
            }
            else 
            {
                ScriptExamine = false;
                if (VerboseOutput) { Console.WriteLine("Script not found in the vault, will return valid."); }
            }
            dbRdr.Close();
            dbConn.Close();
            dbConn.Dispose();
            SQLiteConnection.ClearAllPools();
            GC.Collect();
            if (ScriptExamine)
            {
                FileStream scriptStream = new FileStream(FilePath, FileMode.Open, FileAccess.Read);
                MD5 crSP = new MD5CryptoServiceProvider();
                byte[] hashChar = crSP.ComputeHash(scriptStream);
                scriptStream.Close();
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < hashChar.Length; i++)
                {
                    sb.Append(hashChar[i].ToString("x2").ToUpper());
                }
                string scriptFileHash = sb.ToString();
                if (VerboseOutput) { Console.WriteLine(("MD5 of script file: " + scriptFileHash)); }
                if (ScriptHash == scriptFileHash)
                {
                    res = true;
                    if (VerboseOutput) { Console.WriteLine("MD5 hashes match!"); }
                }
                if (res && !ScriptAllowUnsigned) {
                    PowerShell acHost = PowerShell.Create();
                    if (VerboseOutput) { Console.WriteLine(("PS Instance initialised: " + acHost.InstanceId.ToString())); }
                    Collection<System.Management.Automation.Signature> scriptSig = acHost.AddCommand("Get-AuthenticodeSignature").AddParameter("FilePath", FilePath).Invoke<System.Management.Automation.Signature>();
                    string scriptSigStatus = scriptSig[0].Status.ToString();
                    acHost.Dispose();
                    if (VerboseOutput) { Console.WriteLine(("Script Signature status: " + scriptSigStatus)); }
                    if (scriptSigStatus.Trim().ToLower() == "notsigned")
                    {
                        res = false;
                        Console.Error.WriteLine("Script is unsigned but signature is required");
                    }
                    else if (scriptSigStatus.Trim().ToLower() != "valid")
                    {
                        if (ScriptAllowBroken)
                        {
                            if (VerboseOutput) { Console.WriteLine("Signature is broken but this is tolerated"); }
                        } 
                        else
                        {
                            res = false;
                            Console.Error.WriteLine("Script is signed but signature is broken which is not tolerated");
                        }
                    }
                }
            } else
            {
                res = true;
            }
            return res;
        }

        static PSCredential RetrieveCredential(string FilePath)
        {
            if (!System.IO.File.Exists(FilePath))
            {
                Console.Error.WriteLine(("[SEPH] Script not found: " + FilePath));
                return null;
            }
            string dataFile = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) + "\\Data\\SEPH.sqlite";
            if (!System.IO.File.Exists(dataFile))
            {
                Console.Error.WriteLine(("[SEPH] Vault database not found: " + dataFile));
                return null;
            }
            PSCredential cred = null;
            SQLiteConnection dbConn = new SQLiteConnection("Data Source=" + dataFile + "; Version=3; Read Only=True;");
            dbConn.Open();
            SQLiteCommand dbCmd = dbConn.CreateCommand();
            string scriptName = Path.GetFileNameWithoutExtension(FilePath);
            dbCmd.CommandText = String.Format("SELECT * FROM SCRIPTS WHERE NAME='{0}'", (scriptName.Replace("'", "''")));
            SQLiteDataReader dbRdr = dbCmd.ExecuteReader();
            if (dbRdr.HasRows)
            {
                if (VerboseOutput) { Console.WriteLine("Script found in the vault, will retrieve credential."); }
                dbRdr.Read();
                if (VerboseOutput) { Console.WriteLine(("User name: " + dbRdr["UserName"].ToString())); }
                SecureString secPwd = new NetworkCredential("", dbRdr["Password"].ToString()).SecurePassword;
                cred = new System.Management.Automation.PSCredential(dbRdr["UserName"].ToString(), secPwd);
            }
            else
            {
                if (VerboseOutput) { Console.WriteLine("Script not found in the vault, will return invalid."); }
            }
            dbRdr.Close();
            dbConn.Close();
            dbConn.Dispose();
            SQLiteConnection.ClearAllPools();
            GC.Collect();
            return cred;
        }

    }
}
