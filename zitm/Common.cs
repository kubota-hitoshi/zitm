using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using WinDivertSharp;

namespace zitm
{
    public static class Common
    {
        public static void Log(string msg)
        {
            Console.WriteLine(msg);
            return;
        }

        public static Input RunFilters(List<Func<Input, Input>> filters, Input input)
        {
            for (int i = 0; i < filters.Count; ++i)
                input = filters[i](input);
            return input;
        }

        public static Input InputFillParams(Input input)
        {
            input.NlType = GetNetworkLayerType(input.received_packet);
            byte[] packet = input.received_packet;

            switch (input.NlType)
            {
                case NetworkLayerType.IPv4:

                    byte transport_layer_protocol = packet[9];
                    
                    byte[] destination_ip = new byte[4];
                    Array.Copy(packet, 16, destination_ip, 0, 4);
                    IPAddress ip = new IPAddress(destination_ip);

                    input.IPv4_destination_ip = ip.ToString();

                    byte[] source_ip = new byte[4];
                    Array.Copy(packet, 12, source_ip, 0, 4);
                    IPAddress sip = new IPAddress(source_ip);

                    input.IPv4_source_ip = sip.ToString();

                    byte IHL = (byte)(packet[0] << 4);
                    IHL = (byte)(IHL >> 4);

                    int ip_header_len;

                    if (IHL > 5)
                        ip_header_len = (IHL * 32) / 8;
                    else
                        ip_header_len = 20;

                    input.IPv4_header_len = ip_header_len;

                    if (packet.Length == 20)
                    {
                        input.TlType = TransportLayerType.Empty;
                        break;
                    }
                    
                    switch (transport_layer_protocol)
                    {
                        case 0x06:
                            input.TlType = TransportLayerType.Tcp;

                            byte[] destination_port = new byte[2];
                            Array.Copy(packet, ip_header_len + 2, destination_port, 0, 2);
                            Array.Reverse(destination_port);
                            ushort port = BitConverter.ToUInt16(destination_port, 0);

                            input.TCP_destination_port = port;

                            byte[] source_port = new byte[2];
                            Array.Copy(packet, ip_header_len + 0, source_port, 0, 2);
                            Array.Reverse(source_port);
                            ushort sport = BitConverter.ToUInt16(source_port, 0);

                            input.TCP_source_port = sport;

                            break;
                        case 0x11:
                            input.TlType = TransportLayerType.Udp;

                            byte[] udp_destination_port = new byte[2];
                            Array.Copy(packet, ip_header_len + 2, udp_destination_port, 0, 2);
                            Array.Reverse(udp_destination_port);
                            ushort udp_port = BitConverter.ToUInt16(udp_destination_port, 0);

                            input.UDP_destination_port = udp_port;

                            byte[] udp_source_port = new byte[2];
                            Array.Copy(packet, ip_header_len + 0, udp_source_port, 0, 2);
                            Array.Reverse(udp_source_port);
                            ushort udp_sport = BitConverter.ToUInt16(udp_source_port, 0);

                            input.UDP_source_port = udp_sport;

                            break;
                        default:
                            
                            input.TlType = TransportLayerType.Unknown;
                            break;
                    }


                    break;
                case NetworkLayerType.IPv6:

                    /* TO BE IMPLEMENTED */


                    break;
                case NetworkLayerType.Occ:
                    break;
                case NetworkLayerType.Unknown:
                    break;
                case NetworkLayerType.Empty:
                    break;
                default:
                    break;
            }

            return input;

        }

        public static NetworkLayerType GetNetworkLayerType(byte[] packet)
        {
            if (packet.Length == 0)
                return NetworkLayerType.Empty;

            int ver = packet[0] >> 4;

            if (ver == 4) return NetworkLayerType.IPv4;
            if (ver == 6) return NetworkLayerType.IPv6;

            if (packet.Length >= 16)
            {
                byte[] occ_magic = new byte[16] {
                0x28, 0x7F, 0x34, 0x6B, 0xD4, 0xEF, 0x7A, 0x81, 0x2D, 0x56, 0xB8, 0xD3, 0xAF, 0xC5, 0x45, 0x9C };
                byte[] packet_take16 = new byte[16];
                Array.Copy(packet, 0, packet_take16, 0, 16);

                if (Common.ByteArrayCompare(occ_magic, packet_take16))
                    return NetworkLayerType.Occ;
            }

            return NetworkLayerType.Unknown;
        }

        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
        static extern int memcmp(byte[] b1, byte[] b2, long count);

        public static bool ByteArrayCompare(byte[] b1, byte[] b2)
        {
            // Validate buffers are the same length.
            // This also ensures that the count does not exceed the length of either buffer.  
            return b1.Length == b2.Length && memcmp(b1, b2, b1.Length) == 0;
        }

        public static bool SocketConnected(Socket s)
        {
            bool part1 = s.Poll(1000, SelectMode.SelectRead);
            bool part2 = (s.Available == 0);
            if (part1 && part2)
                return false;
            else
                return true;
        }

        //******************************************************************************//


        public static byte[] RewriteIpHeader(byte[] packet, IPAddress ip_address, RewriteType type)
        {
            int repl_index = 12;
            if (type == RewriteType.Source)
                repl_index = 12;
            if (type == RewriteType.Destination)
                repl_index = 16;


            byte IHL = (byte)(packet[0] << 4);
            IHL = (byte)(IHL >> 4);

            int ip_header_len;

            if (IHL > 5)
                ip_header_len = (IHL * 32) / 8;
            else
                ip_header_len = 20;

            byte[] source_ip = ip_address.GetAddressBytes();
            byte[] checksum = new byte[2];

            Array.Copy(source_ip, 0, packet, repl_index, 4);
            Array.Copy(checksum, 0, packet, 10, 2);


            byte[] header = new byte[ip_header_len];

            Array.Copy(packet, 0, header, 0, ip_header_len);

            ushort ip_checksum = ComputeChecksum(header, 0, ip_header_len);

            checksum = BitConverter.GetBytes(ip_checksum);
            Array.Reverse(checksum);

            Array.Copy(checksum, 0, packet, 10, 2);

            return packet;
        }

        public static byte[] RewriteTcpHeader(byte[] packet, UInt16 port, RewriteType type)
        {
            byte IHL = (byte)(packet[0] << 4);
            IHL = (byte)(IHL >> 4);

            int ip_header_len;

            if (IHL > 5)
                ip_header_len = (IHL * 32) / 8;
            else
                ip_header_len = 20;

            int port_index = ip_header_len + 0;

            if (type == RewriteType.Source)
                port_index = ip_header_len + 0;
            if (type == RewriteType.Destination)
                port_index = ip_header_len + 2;

            byte[] bdst_port = BitConverter.GetBytes(port);

            packet[port_index] = bdst_port[1];
            packet[port_index + 1] = bdst_port[0];

            return RewriteIpTcpChecksum(packet);
        }

        public static byte[] RewriteUdpHeader(byte[] packet, UInt16 port, RewriteType type)
        {
            byte IHL = (byte)(packet[0] << 4);
            IHL = (byte)(IHL >> 4);

            int ip_header_len;

            if (IHL > 5)
                ip_header_len = (IHL * 32) / 8;
            else
                ip_header_len = 20;

            int port_index = ip_header_len + 0;

            if (type == RewriteType.Source)
                port_index = ip_header_len + 0;
            if (type == RewriteType.Destination)
                port_index = ip_header_len + 2;

            byte[] bdst_port = BitConverter.GetBytes(port);

            packet[port_index] = bdst_port[1];
            packet[port_index + 1] = bdst_port[0];

            return RewriteIpUdpChecksum(packet);
        }

        public static ushort ComputeChecksum(byte[] header, int start, int length)
        {
            ushort word16;
            long sum = 0;
            for (int i = start; i < (length + start); i += 2)
            {
                word16 = (ushort)(((header[i] << 8) & 0xFF00)
                + (header[i + 1] & 0xFF));
                sum += (long)word16;
            }

            while ((sum >> 16) != 0)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }

            sum = ~sum;

            return (ushort)sum;
        }

        public static byte[] GetPesudoheader_IPv4Udp(byte[] packet)
        {
            int ip_header_len;

            byte IHL = (byte)(packet[0] << 4);
            IHL = (byte)(IHL >> 4);
            if (IHL > 5) ip_header_len = (IHL * 32) / 8;
            else ip_header_len = 20;

            byte[] sip = new byte[4];
            Array.Copy(packet, 12, sip, 0, 4);

            byte[] dip = new byte[4];
            Array.Copy(packet, 16, dip, 0, 4);

            byte[] proto = new byte[2] { 0x00, packet[9] };

            byte[] budp_length = new byte[2];
            Array.Copy(packet, ip_header_len + 4, budp_length, 0, 2);

            Array.Reverse(budp_length);
            ushort udp_length = BitConverter.ToUInt16(budp_length, 0);
            Array.Reverse(budp_length);

            byte[] udp_header = new byte[6];
            Array.Copy(packet, ip_header_len, udp_header, 0, 6);

            byte[] udp_data = new byte[udp_length - 8];
            Array.Copy(packet, ip_header_len + 8, udp_data, 0, udp_length - 8);

            int ph_len = 12 + 6 + udp_data.Length;
            if ((ph_len % 2) != 0) ++ph_len;


            byte[] pseudo = new byte[ph_len];
            Array.Copy(sip, 0, pseudo, 0, 4);
            Array.Copy(dip, 0, pseudo, 4, 4);
            Array.Copy(proto, 0, pseudo, 8, 2);
            Array.Copy(budp_length, 0, pseudo, 10, 2);
            Array.Copy(udp_header, 0, pseudo, 12, 6);
            Array.Copy(udp_data, 0, pseudo, 18, udp_data.Length);

            return pseudo;
        }

        public static byte[] RewriteIpUdpChecksum(byte[] packet)
        {
            int ip_header_len;

            byte IHL = (byte)(packet[0] << 4);
            IHL = (byte)(IHL >> 4);
            if (IHL > 5) ip_header_len = (IHL * 32) / 8;
            else ip_header_len = 20;

            byte[] pseudo = GetPesudoheader_IPv4Udp(packet);
            ushort cs = ComputeChecksum(pseudo, 0, pseudo.Length);
            byte[] bcs = BitConverter.GetBytes(cs);
            Array.Reverse(bcs);

            Array.Copy(bcs, 0, packet, ip_header_len + 6, 2);

            return packet;
        }

        public static byte[] GetPesudoheader_IPv4Tcp(byte[] packet)
        {
            int ip_header_len;

            byte IHL = (byte)(packet[0] << 4);
            IHL = (byte)(IHL >> 4);
            if (IHL > 5) ip_header_len = (IHL * 32) / 8;
            else ip_header_len = 20;

            byte[] sip = new byte[4];
            Array.Copy(packet, 12, sip, 0, 4);

            byte[] dip = new byte[4];
            Array.Copy(packet, 16, dip, 0, 4);


            byte[] proto = new byte[2] { 0x00, packet[9] };

            int tcp_header_len;

            byte data_offset = (byte)(packet[ip_header_len + 12] >> 4);
            if (data_offset > 5) tcp_header_len = (data_offset * 32) / 8;
            else tcp_header_len = 20;

            byte[] bpacket_total_length = new byte[2] { packet[3], packet[2] };
            ushort packet_total_length = BitConverter.ToUInt16(bpacket_total_length, 0);

            ushort tcp_length = (ushort)(packet_total_length - ip_header_len);
            byte[] b_tcp_length = BitConverter.GetBytes(tcp_length);
            Array.Reverse(b_tcp_length);


            byte[] tcp_header = new byte[tcp_header_len];
            Array.Copy(packet, ip_header_len, tcp_header, 0, tcp_header_len);
            tcp_header[16] = 0x00;
            tcp_header[17] = 0x00;

            byte[] tcp_data = new byte[tcp_length - tcp_header_len];
            Array.Copy(packet, ip_header_len + tcp_header_len, tcp_data, 0, tcp_length - tcp_header_len);

            int ph_len = 12 + tcp_length;
            if ((ph_len % 2) != 0)
            {
                ++ph_len;
            }

            byte[] pseudo = new byte[ph_len];
            Array.Copy(sip, 0, pseudo, 0, 4);
            Array.Copy(dip, 0, pseudo, 4, 4);
            Array.Copy(proto, 0, pseudo, 8, 2);
            Array.Copy(b_tcp_length, 0, pseudo, 10, 2);
            Array.Copy(tcp_header, 0, pseudo, 12, tcp_header_len);
            Array.Copy(tcp_data, 0, pseudo, 12 + tcp_header_len, tcp_length - tcp_header_len);

            return pseudo;
        }

        public static byte[] RewriteIpTcpChecksum(byte[] packet)
        {
            int ip_header_len;

            byte IHL = (byte)(packet[0] << 4);
            IHL = (byte)(IHL >> 4);
            if (IHL > 5) ip_header_len = (IHL * 32) / 8;
            else ip_header_len = 20;

            byte[] pseudo = GetPesudoheader_IPv4Tcp(packet);
            ushort cs = ComputeChecksum(pseudo, 0, pseudo.Length);
            byte[] bcs = BitConverter.GetBytes(cs);
            Array.Reverse(bcs);

            Array.Copy(bcs, 0, packet, ip_header_len + 16, 2);

            return packet;
        }

        public static UInt32 IpToUint32(string ip)
        {
            byte[] bip = IPAddress.Parse(ip).GetAddressBytes();
            Array.Reverse(bip);
            return BitConverter.ToUInt32(bip, 0);
        }

        
        //******************************************************************************//

        [DllImport("Ws2_32.dll")]
        public static extern int getsockname(IntPtr s, IntPtr name, ref int namelen);

        public static UInt16 GetPort(Socket binded_socket)
        {
            IntPtr ptr = Marshal.AllocHGlobal(16);
            int namelen = 16;
            int ret = getsockname(binded_socket.Handle, ptr, ref namelen);
            byte[] bport = new byte[2] { Marshal.ReadByte(ptr, 3), Marshal.ReadByte(ptr, 2) };
            UInt16 port = BitConverter.ToUInt16(bport, 0);
            Marshal.FreeHGlobal(ptr);
            return port;
        }

        //******************************************************************************//

        public static MitmSession CreateMitmSession(Input input, Zitm zit)
        {
            TransportLayerType tltype = input.TlType;
            if (tltype != TransportLayerType.Tcp && tltype != TransportLayerType.Udp)
                throw new NotImplementedException();

            string stltype = "";
            if (tltype == TransportLayerType.Tcp) stltype = "tcp";
            if (tltype == TransportLayerType.Udp) stltype = "udp";

            MitmSession ret = new MitmSession();

            ret.tltype = tltype;
            ret.zit = zit;
            ret.r_allow = new System.Threading.ManualResetEvent(false);

            if (tltype == TransportLayerType.Tcp)
            {
                ret.client = new IPEndPoint(
                    IPAddress.Parse(input.IPv4_source_ip),
                    input.TCP_source_port);

                ret.remote = new IPEndPoint(
                    IPAddress.Parse(input.IPv4_destination_ip),
                    input.TCP_destination_port);

                Socket stcp = new Socket(zit._local.Address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                IPEndPoint ep = new IPEndPoint(zit._local.Address, 0);
                stcp.Bind(ep);

                ret.local = new IPEndPoint(
                    zit._local.Address,
                    Common.GetPort(stcp));

                ret.binded_socket = stcp;
            }

            if (tltype == TransportLayerType.Udp)
            {
                ret.client = new IPEndPoint(
                    IPAddress.Parse(input.IPv4_source_ip),
                    input.UDP_source_port);

                ret.remote = new IPEndPoint(
                    IPAddress.Parse(input.IPv4_destination_ip),
                    input.UDP_destination_port);

                Socket sudp = new Socket(zit._local.Address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                IPEndPoint ep = new IPEndPoint(zit._local.Address, 0);
                sudp.Bind(ep);

                ret.local = new IPEndPoint(
                    zit._local.Address,
                    Common.GetPort(sudp));

                ret.binded_socket = sudp;
            }

            ret.workSocket = input.workSocket;

            //***//

            ret.addr_send = new WinDivertAddress();
            ret.addr_send.Reset();
            ret.addr_send.Direction = WinDivertDirection.Outbound;

            ret.addr_recv = new WinDivertAddress();
            ret.addr_recv.Reset();
            ret.addr_recv.Direction = WinDivertDirection.Outbound;

            ret.forward_handle = WinDivert.WinDivertOpen("false", WinDivertLayer.Network, 0, WinDivertOpenFlags.None);

            //***//

            UInt32 ulocal_ip = Common.IpToUint32(ret.local.Address.ToString());
            UInt32 uremote_ip = Common.IpToUint32(ret.remote.Address.ToString());

            string filter =
                "ip.DstAddr == " + ulocal_ip.ToString() +
                " and ip.SrcAddr == " + uremote_ip.ToString() +
                " and "+ stltype +".DstPort == " + ret.local.Port.ToString() +
                " and "+ stltype +".SrcPort == " + ret.remote.Port.ToString();

            ret.listener_handle = WinDivert.WinDivertOpen(filter, WinDivertLayer.Network, 0, WinDivertOpenFlags.None);
            ret.listener_buffer = new WinDivertBuffer();

            return ret;
        }
    }
}