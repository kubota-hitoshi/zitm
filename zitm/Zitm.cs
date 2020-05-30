using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using WinDivertSharp;

namespace zitm
{
    public class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        public bool Equals(byte[] x, byte[] y)
        {
            return Common.ByteArrayCompare(x, y);
        }

        public int GetHashCode(byte[] obj)
        {
            return StructuralComparisons.StructuralEqualityComparer.GetHashCode(obj);
        }
    }

    public class Zitm
    {
        public List<Func<Input, Input>> InPacketFilters = new List<Func<Input, Input>>();
        public List<Func<Input, Input>> OutPacketFilters = new List<Func<Input, Input>>();

        private Listener _listener;
        public IPEndPoint _local;

        private ConcurrentDictionary<byte[], MitmSession> mitmSessions;

        public Zitm()
        {
            mitmSessions = new ConcurrentDictionary<byte[], MitmSession>(new ByteArrayComparer());
        }

        public void StartListener(IPEndPoint local)
        {
            _local = local;
            _listener = new Listener(local, this);
            _listener.Run();
            return;
        }

        public void Route(Input input)
        {
            input = Common.InputFillParams(input);
            input = Common.RunFilters(InPacketFilters, input);

            if (input.TlType == TransportLayerType.Tcp)
            {
                IPEndPoint _client = new IPEndPoint(IPAddress.Parse(input.IPv4_source_ip), input.TCP_source_port);
                IPEndPoint _remote = new IPEndPoint(IPAddress.Parse(input.IPv4_destination_ip), input.TCP_destination_port);
                MitmSession mitm_session = ProvideMitm(input, _client, _remote);

                lock (mitm_session.deletion_locker)
                {
                    Traffic.TcpRewriteSend(mitm_session, input);
                }

                return;
            }

            if (input.TlType == TransportLayerType.Udp)
            {
                IPEndPoint _client = new IPEndPoint(IPAddress.Parse(input.IPv4_source_ip), input.UDP_source_port);
                IPEndPoint _remote = new IPEndPoint(IPAddress.Parse(input.IPv4_destination_ip), input.UDP_destination_port);
                MitmSession mitm_session = ProvideMitm(input, _client, _remote);

                lock (mitm_session.deletion_locker)
                {
                    Traffic.UdpRewriteSend(mitm_session, input);
                }

                return;
            }
            return;
        }

        public void Response(Input input)
        {
            byte[] transfer_unit = new byte[input.received_packet.Length + 2];
            byte[] bsize = BitConverter.GetBytes((ushort)input.received_packet.Length);
            Array.Reverse(bsize);
            Array.Copy(bsize, 0, transfer_unit, 0, 2);
            Array.Copy(input.received_packet, 0, transfer_unit, 2, input.received_packet.Length);

            if (Common.SocketConnected(input.workSocket))
            {
                input = Common.RunFilters(OutPacketFilters, input);

                input.workSocket.BeginSend(
                    transfer_unit, 0, transfer_unit.Length,
                    SocketFlags.None, new AsyncCallback(EndSendCallback), input.workSocket);
            }
        }

        private void EndSendCallback(IAsyncResult ar)
        {
            Socket ws = (Socket)ar.AsyncState;
            ws.EndSend(ar);
            return;
        }

        private MitmSession ProvideMitm(Input input, IPEndPoint client, IPEndPoint remote)
        {
            Zitm this_obj = this;

            MitmSession rmitm = mitmSessions.GetOrAdd(
                GetKey(client,remote),
                _ => {
                    MitmSession mitm = Common.CreateMitmSession(input, this_obj);

                    if (input.TlType == TransportLayerType.Udp)
                        Task.Run(() => Traffic.T_UdpReceiver(mitm));

                    if (input.TlType == TransportLayerType.Tcp)
                        Task.Run(() => Traffic.T_TcpReceiver(mitm));

                    return mitm; } 
                ) ;

            return rmitm;
        }

        public void RemoveSession(MitmSession session)
        {
            MitmSession unused;
            mitmSessions.TryRemove(GetKey(session.client, session.remote), out unused);

            lock (session.deletion_locker)
            {
                WinDivert.WinDivertClose(session.forward_handle);
                session.binded_socket.Close();

                WinDivert.WinDivertClose(session.listener_handle);
                session.listener_buffer.Dispose();
            }

            return;
        }

        private byte[] GetKey(IPEndPoint client, IPEndPoint remote)
        {
            byte[] key = new byte[6 + 6];
            Array.Copy(client.Address.GetAddressBytes(), 0, key, 0, 4);
            Array.Copy(BitConverter.GetBytes((UInt16)client.Port), 0, key, 4, 2);
            Array.Copy(remote.Address.GetAddressBytes(), 0, key, 6, 4);
            Array.Copy(BitConverter.GetBytes((UInt16)remote.Port), 0, key, 10, 2);

            return key;
        }
    }
}