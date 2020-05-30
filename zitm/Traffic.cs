using System;
using System.Threading;
using WinDivertSharp;

namespace zitm
{
    public static class Traffic
    {
        public static void UdpRewriteSend(MitmSession session, Input input)
        {
            session.r_allow.WaitOne();

            byte[] packet = input.received_packet;

            packet = Common.RewriteIpHeader(packet, session.local.Address, RewriteType.Source);
            packet = Common.RewriteUdpHeader(packet, (ushort)session.local.Port, RewriteType.Source);

            bool succ = WinDivert.WinDivertSend(session.forward_handle, new WinDivertBuffer(packet), (uint)packet.Length, ref session.addr_send);
            return;
        }

        public static byte[] UdpRewriteRecv(MitmSession session)
        {
            bool succ = WinDivert.WinDivertRecv(session.listener_handle, session.listener_buffer, ref session.addr_recv);

            UInt16 ulen = BitConverter.ToUInt16(new byte[2] { session.listener_buffer[3], session.listener_buffer[2] }, 0);

            byte[] packet = new byte[ulen];
            for (int i = 0; i < ulen; ++i)
                packet[i] = session.listener_buffer[i];

            packet = Common.RewriteIpHeader(packet, session.client.Address, RewriteType.Destination);
            packet = Common.RewriteUdpHeader(packet, (ushort)session.client.Port, RewriteType.Destination);

            return packet;

        }

        public static void TcpRewriteSend(MitmSession session, Input input)
        {
            session.r_allow.WaitOne();

            byte[] packet = input.received_packet;

            packet = Common.RewriteIpHeader(packet, session.local.Address, RewriteType.Source);
            packet = Common.RewriteTcpHeader(packet, (ushort)session.local.Port, RewriteType.Source);

            bool succ = WinDivert.WinDivertSend(session.forward_handle, new WinDivertBuffer(packet), (uint)packet.Length, ref session.addr_send);
            return;

        }

        public static byte[] TcpRewriteRecv(MitmSession session)
        {
            bool succ = WinDivert.WinDivertRecv(session.listener_handle, session.listener_buffer, ref session.addr_recv);

            UInt16 ulen = BitConverter.ToUInt16(new byte[2] { session.listener_buffer[3], session.listener_buffer[2] }, 0);

            byte[] packet = new byte[ulen];
            for (int i = 0; i < ulen; ++i)
                packet[i] = session.listener_buffer[i];

            packet = Common.RewriteIpHeader(packet, session.client.Address, RewriteType.Destination);
            packet = Common.RewriteTcpHeader(packet, (ushort)session.client.Port, RewriteType.Destination);

            return packet;
        }

        public static void T_TcpReceiver(MitmSession session)
        {
            session.r_allow.Set();

            for (; ; )
            {
                byte[] packet = new byte[0];
                IAsyncResult result;
                Action action = () =>
                {
                    packet = TcpRewriteRecv(session);
                };

                result = action.BeginInvoke(null, null);

                if (result.AsyncWaitHandle.WaitOne(1000))
                {
                    Input output = new Input
                    {
                        received_packet = packet,
                        time_received = DateTime.UtcNow,
                        workSocket = session.workSocket
                    };

                    session.zit.Response(output);
                    Thread.Sleep(0);
                }
                else break;
            }

            session.zit.RemoveSession(session);
            return;
        }

        public static void T_UdpReceiver(MitmSession session)
        {
            session.r_allow.Set();

            for (; ; )
            {
                byte[] packet = new byte[0];
                IAsyncResult result;
                Action action = () =>
                {
                    packet = UdpRewriteRecv(session);
                };

                result = action.BeginInvoke(null, null);

                if (result.AsyncWaitHandle.WaitOne(1000))
                {
                    Input output = new Input
                    {
                        received_packet = packet,
                        time_received = DateTime.UtcNow,
                        workSocket = session.workSocket
                    };

                    session.zit.Response(output);
                    Thread.Sleep(0);
                }
                else break;
            }

            session.zit.RemoveSession(session);
            return;
        }
    }
}