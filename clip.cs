using System;
using System.IO;
using System.Windows.Forms;
using System.Drawing;

class ClipboardMonitor
{
    private static string lastClipboardText = string.Empty;
    private static string lastClipboardHtml = string.Empty;
    private static Bitmap lastClipboardImage = null;
    private static readonly string tempFolder = Path.Combine(Path.GetTempPath(), "clip");
    private static Timer clipboardCheckTimer;

    [STAThread]
    static void Main()
    {
        // Ensure the temp folder exists
        Directory.CreateDirectory(tempFolder);

        // Set up a timer to check the clipboard every second
        clipboardCheckTimer = new Timer();
        clipboardCheckTimer.Interval = 1000; // 1 second
        clipboardCheckTimer.Tick += CheckClipboard;
        clipboardCheckTimer.Start();

        // Keep the application running
        Application.Run();
    }

    private static void CheckClipboard(object sender, EventArgs e)
    {
        try
        {
            IDataObject clipboardObject = Clipboard.GetDataObject();
            if (clipboardObject == null) return;

            // Check for text
            if (clipboardObject.GetDataPresent(DataFormats.Text))
            {
                string text = (string)clipboardObject.GetData(DataFormats.Text);
                if (text != lastClipboardText)
                {
                    lastClipboardText = text;
                    SaveToFile(text, "txt");
                }
            }

            // Check for images
            if (clipboardObject.GetDataPresent(DataFormats.Bitmap))
            {
                Bitmap image = (Bitmap)clipboardObject.GetData(DataFormats.Bitmap);
                if (lastClipboardImage == null || !CompareImages(image, lastClipboardImage))
                {
                    lastClipboardImage = new Bitmap(image);
                    SaveToFile(image, "png");
                }
            }

            // Check for hyperlinks (HTML)
            if (clipboardObject.GetDataPresent(DataFormats.Html))
            {
                string html = (string)clipboardObject.GetData(DataFormats.Html);
                if (html != lastClipboardHtml)
                {
                    lastClipboardHtml = html;
                    SaveToFile(html, "html");
                }
            }
        }
        catch
        {
            // Handle exceptions silently to avoid crashing
        }
    }

    private static void SaveToFile(object content, string extension)
    {
        string timestamp = DateTime.Now.ToString("yyyy-MM-dd-HH-mm-ss");
        string filePath = Path.Combine(tempFolder, string.Format("{0}.{1}", timestamp, extension));

        if (content is string)
        {
            File.WriteAllText(filePath, (string)content);
        }
        else if (content is Bitmap)
        {
            ((Bitmap)content).Save(filePath);
        }
    }

    private static bool CompareImages(Bitmap img1, Bitmap img2)
    {
        if (img1.Width != img2.Width || img1.Height != img2.Height)
            return false;

        for (int x = 0; x < img1.Width; x++)
        {
            for (int y = 0; y < img1.Height; y++)
            {
                if (img1.GetPixel(x, y) != img2.GetPixel(x, y))
                    return false;
            }
        }
        return true;
    }
}
