### Introduction

ZITM is a DotNET library that uses WinDivert driver.

### Features

* Service for OpenVPN client.
* Pcap writer

### Known Use Cases

* Reverse engineering of Android app network traffic.
* Basic VPN server.
* Capture network traffic of clients using built-in .pcap writer.

### Example

```cs
PcapWriter pwr = new PcapWriter("capture2.pcap");

Zitm zitm = new Zitm();

zitm.InPacketFilters.Add(
    (Input packet_input) =>
    {
        pwr.AppendPacket(packet_input);
        return packet_input;
    });

zitm.OutPacketFilters.Add(
     (Input packet_input) =>
     {
         pwr.AppendPacket(packet_input);
         return packet_input;
     }
);

zitm.StartListener(
   new System.Net.IPEndPoint(
      IPAddress.Parse("192.168.1.55"), 1194));
```

### Requirements

* Windows 10
* DotNET Framework v4.6
* WinDivert
* Administrator


