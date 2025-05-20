using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;

namespace mySync
{
    static class Program
    {
        /// <summary>
        /// Hlavní vstupní bod aplikace.
        /// </summary>
        static void Main()
        {
            ServiceBase[] ServicesToRun;
            ServicesToRun = new ServiceBase[]
            {
                new Service1()
            };
            ServiceBase.Run(ServicesToRun);
        }
    }
}

// Compile command:
// csc.exe /target:exe /out:mySync.exe /reference:"%WINDIR%\Microsoft.NET\Framework\v4.0.30319\System.ServiceProcess.dll" Service1.cs Service1.Designer.cs Program.cs
