using System;
using System.IO;

namespace zitm
{
    public class PcapWriter
    {
        private string _path;
        private FileStream fs;

        public PcapWriter(string path)
        {
            _path = path;
            byte[] global_header = new byte[24];

            Array.Copy(new byte[4] { 0xD4, 0xC3, 0xB2, 0xA1 }, 0, global_header, 0, 4);
            Array.Copy(new byte[2] { 0x02, 0x00 }, 0, global_header, 4, 2);
            Array.Copy(new byte[2] { 0x04, 0x00 }, 0, global_header, 6, 2);
            Array.Copy(new byte[4] { 0x00, 0x00, 0x00, 0x00 }, 0, global_header, 8, 4);
            Array.Copy(new byte[4] { 0x00, 0x00, 0x00, 0x00 }, 0, global_header, 12, 4);
            Array.Copy(new byte[4] { 0x00, 0x00, 0x04, 0x00 }, 0, global_header, 16, 4);
            Array.Copy(new byte[4] { 0x01, 0x00, 0x00, 0x00 }, 0, global_header, 20, 4);

            File.WriteAllBytes(_path, global_header);
            fs = new FileStream(path, FileMode.Append, FileAccess.Write);
        }

        public void AppendPacket(Input input)
        {
            DateTime now = input.time_received;
            byte[] packet = input.received_packet;

            Int32 unixTimestamp = (Int32)(now.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;

            string micro = now.ToString("ffffff");
            uint umicro = uint.Parse(micro);

            Int32 ethernet2_header_length = 14;

            //-- write packet metaheader
            byte[] packet_metaheader = new byte[16];
            Array.Copy(BitConverter.GetBytes(unixTimestamp), 0, packet_metaheader, 0, 4);
            Array.Copy(BitConverter.GetBytes(umicro), 0, packet_metaheader, 4, 4);
            Array.Copy(BitConverter.GetBytes(ethernet2_header_length + packet.Length), 0, packet_metaheader, 8, 4);
            Array.Copy(BitConverter.GetBytes(ethernet2_header_length + packet.Length), 0, packet_metaheader, 12, 4);

            NetworkLayerType ptype = Common.GetNetworkLayerType(packet);

            byte[] type = new byte[2];

            switch (ptype)
            {
                case NetworkLayerType.IPv4:
                    type = new byte[2] { 0x08, 0x00 };
                    break;
                case NetworkLayerType.IPv6:
                    type = new byte[2] { 0x86, 0xDD };
                    break;
                case NetworkLayerType.Occ:
                    return;
                case NetworkLayerType.Empty:
                    return;
                case NetworkLayerType.Unknown:
                    File.AppendAllText("pcapwriter.log", "pcapwriter err unknown : \r\n" + BitConverter.ToString(packet).Replace("-", "") + "\r\n");
                    return;
                default:
                    break;
            }

            //-- write ethernet 2 frame
            byte[] ethernet2_frame = new byte[ethernet2_header_length];
            Array.Copy(new byte[6] { 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA }, 0, ethernet2_frame, 0, 6);
            Array.Copy(new byte[6] { 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB }, 0, ethernet2_frame, 6, 6);
            Array.Copy(type, 0, ethernet2_frame, 12, 2);


            //-- write ip packet
            byte[] record = new byte[packet_metaheader.Length + ethernet2_header_length + packet.Length];
            Array.Copy(packet_metaheader, 0, record, 0, packet_metaheader.Length);
            Array.Copy(ethernet2_frame, 0, record, packet_metaheader.Length, ethernet2_header_length);
            Array.Copy(packet, 0, record, packet_metaheader.Length + ethernet2_header_length, packet.Length);

            //-- write to file
            fs.BeginWrite(record, 0, record.Length, new AsyncCallback(EndWriteCallback), null);

            return;
        }

        private void EndWriteCallback(IAsyncResult ar)
        {
            fs.EndWrite(ar);
            return;
        }
    }
}