using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Net;
using System.IO;

namespace ConsoleApp1
{
    class TcpClient
    {
        static void Main(string[] args)
        {
            byte[] buffer = new byte[1024];

            try
            {
                IPHostEntry ipHostInfo = Dns.GetHostEntry(Dns.GetHostName());
                IPAddress ipAddress = ipHostInfo.AddressList[0];
                IPEndPoint remoteEP = new IPEndPoint(ipAddress, 60000);

                Socket sender = new Socket(ipAddress.AddressFamily,
                    SocketType.Stream, ProtocolType.Tcp);

                try
                {
                    sender.Connect(remoteEP);

                    Console.WriteLine("Socket connected to {0}",
                        sender.RemoteEndPoint.ToString());

                    // Encode the data string into a byte array.  
                    byte[] msg = Encoding.ASCII.GetBytes("Hello server!");

                    // Send the data through the socket.  
                    int bytesSent = sender.Send(msg);

                    // Receive the response from the remote device.  
                    sender.SendFile("C:/Users/Zakaru99/source/repos/ConsoleApp1/ConsoleApp1/test.py");

                    Console.WriteLine("Done Sending Python File");

                    var stream = new NetworkStream(sender);
                    var output = System.IO.File.Create("C:/Users/Zakaru99/source/repos/ConsoleApp1/ConsoleApp1/received_file.html");
                    int bytesRead;

                    sender.Shutdown(SocketShutdown.Send);

                    while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        output.Write(buffer, 0, bytesRead);
                    }

                    Console.WriteLine("Successfully got the html file");
                    // Release the socket.  

                    sender.Close();

                    System.Diagnostics.Process.Start("C:/Users/Zakaru99/source/repos/ConsoleApp1/ConsoleApp1/received_file.html");

                }
                catch (ArgumentNullException ane)
                {
                    Console.WriteLine("ArgumentNullException : {0}", ane.ToString());
                }
                catch (SocketException se)
                {
                    Console.WriteLine("SocketException : {0}", se.ToString());
                }
                catch (Exception e)
                {
                    Console.WriteLine("Unexpected exception : {0}", e.ToString());
                }
            } catch(Exception e)
            {
                Console.WriteLine(e.ToString());
            }
        }
    }
}
