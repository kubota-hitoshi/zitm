using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace zitm
{
    public class StateObject
    {
        public Socket workSocket = null;
        public byte[] buffer;
        public byte[] buffer_length = new byte[2];
        public UInt16 plen;
        public NetworkStream ns;

        public int length_bytes_remaining;
        public int length_total_size;

        public int datagram_bytes_remaining;
        public int datagram_total_size;
    }

    public class Listener
    {
        public static ManualResetEvent allDone = new ManualResetEvent(false);

        public IPEndPoint localEndPoint;
        public Zitm _zit;

        public Listener(IPEndPoint server, Zitm zit)
        {
            localEndPoint = server;
            _zit = zit;
        }

        public void Run()
        {
            Thread t = new Thread(new ThreadStart(StartListening));
            t.Start();
            return;
        }

        public void StartListening()
        {
            // Create a TCP/IP socket.  
            Socket listener = new Socket(localEndPoint.AddressFamily,
                SocketType.Stream, ProtocolType.Tcp);

            // Bind the socket to the local endpoint and listen for incoming connections.  
            try
            {
                listener.Bind(localEndPoint);
                listener.Listen(100);

                while (true)
                {
                    // Set the event to nonsignaled state.  
                    allDone.Reset();

                    // Start an asynchronous socket to listen for connections.  
                    Common.Log("Waiting for a connection...");
                    listener.BeginAccept(
                        new AsyncCallback(AcceptCallback),
                        listener);

                    // Wait until a connection is made before continuing.  
                    allDone.WaitOne();
                }

            }
            catch (Exception e)
            {
                Common.Log(e.ToString());
            }
            return;
        }

        public void AcceptCallback(IAsyncResult ar)
        {
            // Signal the main thread to continue.  
            allDone.Set();

            // Get the socket that handles the client request.  
            Socket listener = (Socket)ar.AsyncState;
            Socket handler = listener.EndAccept(ar);

            // Create the state object.  
            StateObject state = new StateObject();
            state.workSocket = handler;

            state.ns = new NetworkStream(handler);

            state.length_bytes_remaining = 2;
            state.length_total_size = 2;

            try
            {
                state.ns.BeginRead(state.buffer_length, 0, 2,
                    new AsyncCallback(ReadLengthCallback), state);
            }
            catch (Exception e)
            {
                Common.Log("AcceptCallback() : " + e.Message);
                state.ns.Dispose();
            }
        }

        public void ReadLengthCallback(IAsyncResult ar)
        {
            StateObject state = (StateObject)ar.AsyncState;

            try
            {
                int bytesRead = state.ns.EndRead(ar);

                if (bytesRead > 0)
                {
                    if (bytesRead != state.length_bytes_remaining)
                    {
                        state.length_bytes_remaining = state.length_bytes_remaining - bytesRead;

                        state.ns.BeginRead(
                            state.buffer_length,
                            (state.length_total_size - state.length_bytes_remaining),
                            state.length_bytes_remaining,
                            new AsyncCallback(ReadLengthCallback), state);
                        return;
                    }

                    byte[] blen = new byte[] { (byte)state.buffer_length[1], (byte)state.buffer_length[0] };
                    UInt16 plen = BitConverter.ToUInt16(blen, 0);
                    state.plen = plen;

                    state.buffer = new byte[plen];

                    state.datagram_bytes_remaining = state.plen;
                    state.datagram_total_size = state.plen;

                    state.ns.BeginRead(state.buffer, 0, state.datagram_bytes_remaining,
                    new AsyncCallback(ReadDatagramCallback), state);
                }
            }
            catch (Exception e)
            {
                Common.Log("ReadLengthCallback() : " + e.Message);
                state.ns.Dispose();
            }
        }

        public void ReadDatagramCallback(IAsyncResult ar)
        {
            StateObject state = (StateObject)ar.AsyncState;

            try
            {
                int bytesRead = state.ns.EndRead(ar);

                if (bytesRead > 0)
                {
                    if (bytesRead != state.datagram_bytes_remaining)
                    {
                        state.datagram_bytes_remaining = state.datagram_bytes_remaining - bytesRead;

                        state.ns.BeginRead(
                            state.buffer,
                            (state.datagram_total_size - state.datagram_bytes_remaining),
                            state.datagram_bytes_remaining,
                            new AsyncCallback(ReadDatagramCallback), state);
                        return;
                    }
                    //; state.buffer contains datagram

                    Input input = new Input()
                    {
                        workSocket = state.workSocket,
                        received_packet = state.buffer,
                        time_received = DateTime.UtcNow
                    };

                    _zit.Route(input);

                    state.length_bytes_remaining = 2;
                    state.length_total_size = 2;

                    state.ns.BeginRead(state.buffer_length, 0, 2,
                    new AsyncCallback(ReadLengthCallback), state);
                }

            }
            catch (Exception e)
            {
                Common.Log("ReadDatagramCallback() : " + e.Message);
                state.ns.Dispose();
            }
        }
    }
}