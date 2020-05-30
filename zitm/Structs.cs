using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using WinDivertSharp;

namespace zitm
{
    public enum RewriteType
    {
        Source,
        Destination
    }

    public enum NetworkLayerType
    {
        IPv4 = 1,
        IPv6 = 2,
        Occ = 3,
        Unknown = 998,
        Empty = 999
    }

    public enum TransportLayerType
    {
        Udp = 1,
        Tcp = 2,
        Unknown = 998,
        Empty = 999
    }

    public struct Input
    {
        public Socket workSocket;
        public byte[] received_packet;
        public DateTime time_received;

        public NetworkLayerType NlType;

        //IPv4
        public string IPv4_source_ip;
        public string IPv4_destination_ip;
        public int IPv4_header_len;

        public TransportLayerType TlType;

        //TCP
        public int TCP_source_port;
        public int TCP_destination_port;

        //UDP
        public int UDP_source_port;
        public int UDP_destination_port;

    }

    public class MitmSession
    {
        public IPEndPoint client;
        public IPEndPoint local;
        public IPEndPoint remote;
        public Socket workSocket;
        public WinDivertAddress addr_send;
        public WinDivertAddress addr_recv;
        public IntPtr forward_handle;
        public IntPtr listener_handle;
        public WinDivertBuffer listener_buffer;
        public TransportLayerType tltype;
        public Zitm zit;
        public ManualResetEvent r_allow;
        public Socket binded_socket;
        public readonly object deletion_locker = new Object();
    }
}
