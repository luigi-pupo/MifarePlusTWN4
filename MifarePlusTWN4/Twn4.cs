using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Remoting.Contexts;
using System.Runtime.Remoting.Messaging;
using System.Text;
using System.Threading.Tasks;

namespace MifarePlusTWN4
{
    public class Twn4
    {
        public static int hContext;

        private static int iSCsts = 255;



        private static int hCard = -1;
        private static uint pdwActiveProtocol = 2u;

        private static SCARD_READERSTATE sReaderState;
        private static SCARD_READERSTATE[] sReaderState_arr = new SCARD_READERSTATE[1];



        private enum SCARD_ERR_T : uint
        {
            SCARD_S_SUCCESS = 0x0
            , SCARD_F_INTERNAL_ERROR = 0x80100001

        }


        private enum SCARD_SCOPE
        {
            // The context is a user context, and any database operations are performed within the
            // domain of the user.
            SCARD_SCOPE_USER = 0
          // The context is that of the current terminal, and any database operations are performed
          // within the domain of that terminal. (The calling application must have appropriate
          // access permissions for any database actions.)             
          ,
            SCARD_SCOPE_TERMINAL = 1
            // The context is the system context, and any database operations are performed within the
            // domain of the system.  (The calling application must have appropriate access
            // permissions for any database actions.)      
            , SCARD_SCOPE_SYSTEM = 2
        }
        private enum BeepTypes
        {
            Simple = -1,
            Ok = 0,
            IconHand = 16,
            IconQuestion = 32,
            IconExclamation = 48,
            IconAsterisk = 64
        }

        private static void MessageBeep(BeepTypes type)
        {
            if (!MessageBeep((uint)type))
            {
                int lastWin32Error = Marshal.GetLastWin32Error();
                throw new Win32Exception(lastWin32Error);
            }
        }

        [DllImport("User32.dll", SetLastError = true)]
        private static extern bool MessageBeep(uint beepType);


        [StructLayout(LayoutKind.Sequential)]
        private class SCARD_IO_REQUEST
        {
            internal uint dwProtocol;
            internal int cbPciLength;
        }

        [DllImport("winscard.dll")]
        private static extern int SCardEstablishContext(int dwScope,
                                            IntPtr pvReserved1,
                                            IntPtr pvReserved2,
                                            out int phContext);

        [DllImport("winscard.dll", EntryPoint = "SCardListReadersA", CharSet = CharSet.Ansi)]
        private static extern int SCardListReaders(
          int hContext,
          byte[] mszGroups,
          byte[] mszReaders,
          ref UInt32 pcchReaders);


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct SCARD_READERSTATE
        {
            /// Reader
            [MarshalAs(UnmanagedType.LPWStr)]
            public string szReader;
            /// User Data
            public IntPtr pvUserData;
            /// Current State
            public UInt32 dwCurrentState;
            /// Event State/ New State
            public UInt32 dwEventState;
            /// ATR Length
            public UInt32 cbAtr;
            /// Card ATR
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] rgbAtr;
        }

        private enum SCardState : uint
        {
            /// Unware
            UNAWARE = 0x00000000,
            /// State Ignored
            IGNORE = 0x00000001,
            /// State changed
            CHANGED = 0x00000002,
            /// State Unknown
            UNKNOWN = 0x00000004,
            /// State Unavilable
            UNAVAILABLE = 0x00000008,
            /// State empty
            EMPTY = 0x00000010,
            /// Card Present
            PRESENT = 0x00000020,
            /// ATR mathched
            ATRMATCH = 0x00000040,
            /// In exclusive use
            EXCLUSIVE = 0x00000080,
            /// In use
            INUSE = 0x00000100,
            /// Mute State
            MUTE = 0x00000200,
            /// Card unpowered
            UNPOWERED = 0x00000400
        }

        [DllImport("winscard.dll", EntryPoint = "SCardGetStatusChange", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int SCardGetStatusChange(int hContext,
                                                int dwTimeout,
                                                [In, Out] SCARD_READERSTATE[] rgReaderStates,
                                                int cReaders);

        private enum SHARE_MODE_T : uint
        {
            SCARD_SHARE_SHARED = 0x00000002         // This application will allow others to share the reader 
          ,
            SCARD_SHARE_EXCLUSIVE = 0x00000001    // This application will NOT allow others to share the reader
            , SCARD_SHARE_DIRECT = 0x00000003       // Direct control of the reader, even without a card     
        }

        private enum PREFERRED_PROTOCOL : uint
        {
            SCARD_PROTOCOL_T0 = 0x00000001          // Use the T=0 protocol (value = 0x00000001)
          ,
            SCARD_PROTOCOL_T1 = 0x00000002        // Use the T=1 protocol (value = 0x00000002)
            , CARD_PROTOCOL_RAW = 0x00000004        // Use with memory type cards (value = 0x00000004)
        }

        [DllImport("winscard.dll", EntryPoint = "SCardConnect", CharSet = CharSet.Auto)]
        private static extern int SCardConnect(int hContext,
                                               [MarshalAs(UnmanagedType.LPTStr)] string szReader,
                                               UInt32 dwShareMode,
                                               UInt32 dwPreferredProtocols,
                                               out int phCard,
                                               out UInt32 pdwActiveProtocol);

        [DllImport("winscard.dll")]
        private static extern int SCardTransmit(int hCard,
                                                SCARD_IO_REQUEST pioSendPci,
                                                byte[] pbSendBuffer,
                                                int cbSendLength,
                                                SCARD_IO_REQUEST pioRecvPci,
                                                byte[] pbRecvBuffer,
                                                ref int pcbRecvLength);

        [DllImport("winscard.dll", EntryPoint = "SCardControl", CharSet = CharSet.Auto)]
        private static extern int SCardControl(int hCard,
                                                UInt32 controlcode,
                                                byte[] pbSendBuffer,
                                                int cbSendLength,
                                                byte[] pbRecvBuffer,
                                                int pcRecvBuffSize,
                                                ref int pcbRecvLength);

        [DllImport("winscard.dll")]
        private static extern int SCardReleaseContext(int hContext);



        [DllImport("kernel32.dll", SetLastError = true)]
        private extern static IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll")]
        public extern static void FreeLibrary(IntPtr handle);

        [DllImport("kernel32.dll")]
        private extern static IntPtr GetProcAddress(IntPtr handle, string procName);

        [DllImport("winscard.dll")]
        private static extern int SCardDisconnect(int hCard, int dwDisposition);

        public bool listaLettori(out string[] sReaderName, out int iReadersFound)
        {
            UInt32 pcchReaders = 0;
            int nullindex = -1;
            char nullchar = (char)0;
            int iStartSubString = 0;

            iReadersFound = 0;

            sReaderName = new string[5];
            MessageBeep(BeepTypes.Ok);

            iSCsts = SCardEstablishContext((int)SCARD_SCOPE.SCARD_SCOPE_USER, IntPtr.Zero, IntPtr.Zero, out hContext);
            if (iSCsts == (int)SCARD_ERR_T.SCARD_S_SUCCESS)
            {
                //get readers buffer len
                iSCsts = SCardListReaders(hContext, null, null, ref pcchReaders);
                byte[] mszReaders = new byte[pcchReaders];

                // fill readers' buffer
                iSCsts = SCardListReaders(hContext, null, mszReaders, ref pcchReaders);
                if (iSCsts == (int)SCARD_ERR_T.SCARD_S_SUCCESS)
                {
                    ASCIIEncoding ascii = new ASCIIEncoding();
                    string currbuff = ascii.GetString(mszReaders);
                    int len = (int)pcchReaders;
                    nullindex = 0;

                    do
                    {
                        iStartSubString = nullindex;
                        nullindex = currbuff.IndexOf(nullchar, nullindex);   //get null end character
                        sReaderName[iReadersFound] = currbuff.Substring(iStartSubString, nullindex - iStartSubString);
                        nullindex += 1;
                        if (sReaderName[iReadersFound] != "")
                            iReadersFound += 1;
                    } while (nullindex < len);
                    if (iReadersFound == 0)
                        return false;
                }
                else
                {
                    MessageBeep(BeepTypes.IconExclamation);
                    return false;
                }
            }
            else
            {
                MessageBeep(BeepTypes.IconExclamation);
                return false;
            }

            return true;
        }

        private static bool IsCardPresent(string sReader)
        {
            bool result = false;
            sReaderState.szReader = sReader;
            sReaderState.dwCurrentState = 16u;
            sReaderState.dwEventState = 16u;
            sReaderState_arr[0] = sReaderState;
            iSCsts = SCardGetStatusChange(hContext, 500, sReaderState_arr, 1);
            sReaderState = sReaderState_arr[0];
            if (iSCsts == 0)
            {
                if ((sReaderState.dwEventState & 0x20) == 32)
                {
                    result = true;
                }
            }
            else
            {
                return false;
            }

            return result;
        }
        public bool Connetti(out int stato, string nomelettore)
        {
            if (IsCardPresent(nomelettore))
            {
                iSCsts = SCardConnect(hContext, nomelettore, 2u, 2u, out hCard, out pdwActiveProtocol);
                if (iSCsts == 0)
                {
                    stato = iSCsts;
                    return true;
                }

                stato = iSCsts;
                return true;
            }

            stato = iSCsts;
            return false;
        }

        public bool Disconnetti()
        {
            iSCsts = SCardDisconnect(hCard, 2);

            return iSCsts == (int)SCARD_ERR_T.SCARD_S_SUCCESS;
        }

        public bool RestituisciUID(out string uid, out string status)
        {
            SCARD_IO_REQUEST ioRecv = new SCARD_IO_REQUEST();
            ioRecv.cbPciLength = 255;

            SCARD_IO_REQUEST ioRequest = new SCARD_IO_REQUEST();
            ioRequest.dwProtocol = (UInt32)PREFERRED_PROTOCOL.SCARD_PROTOCOL_T1;
            ioRequest.cbPciLength = 8;

            byte[] pbRecvBuffer = new byte[255];
            int pcbRecvLength = 255;

            string dainviareHEX = "FFCA000000";

            List<byte> txbuff_list = new List<byte>();
            for (int i = 0; i < dainviareHEX.Length - 1; i += 2)
            {
                txbuff_list.Add(Convert.ToByte(dainviareHEX.Substring(i, 2), 16));
            }
            int numero_elementi = txbuff_list.Count;
            byte[] txbuff = new byte[numero_elementi];
            for (int i = 0; i < numero_elementi; i++)
            {
                txbuff[i] = txbuff_list[i];
            }
            int txbuff_size = dainviareHEX.Length / 2;

            SCardTransmit(hCard, ioRequest, txbuff, txbuff_size, (SCARD_IO_REQUEST)null, pbRecvBuffer, ref pcbRecvLength);

            string ris_hex = string.Empty;

            ris_hex = BitConverter.ToString(pbRecvBuffer).Replace("-", "");

            if (pcbRecvLength >= 2  && pcbRecvLength!=255)
            {
                if (ris_hex.Substring((pcbRecvLength*2) - 4, 4) == "9000")
                {
                    uid = ris_hex.Substring(0, (pcbRecvLength*2)-4);
                    status = ris_hex.Substring((pcbRecvLength * 2) - 4, 4);
                    return true;
                }
                else
                {
                    uid = string.Empty;
                    status = ris_hex.Substring((pcbRecvLength * 2) - 4, 4);
                    return false;
                }
            }
            else
            {
                uid = string.Empty;
                status = "BUFFER DI RISPOSTA VUOTO";
                return false;
            }

            
        }
        
        public bool Restituisci__ATS_SL1(out string uid, out string status)
        {
            SCARD_IO_REQUEST ioRecv = new SCARD_IO_REQUEST();
            ioRecv.cbPciLength = 255;

            SCARD_IO_REQUEST ioRequest = new SCARD_IO_REQUEST();
            ioRequest.dwProtocol = (UInt32)PREFERRED_PROTOCOL.SCARD_PROTOCOL_T1;
            ioRequest.cbPciLength = 8;

            byte[] pbRecvBuffer = new byte[255];
            int pcbRecvLength = 255;

            string dainviareHEX = "3B8F8001804F0CA000000306030037000000005C";

            List<byte> txbuff_list = new List<byte>();
            for (int i = 0; i < dainviareHEX.Length - 1; i += 2)
            {
                txbuff_list.Add(Convert.ToByte(dainviareHEX.Substring(i, 2), 16));
            }
            int numero_elementi = txbuff_list.Count;
            byte[] txbuff = new byte[numero_elementi];
            for (int i = 0; i < numero_elementi; i++)
            {
                txbuff[i] = txbuff_list[i];
            }
            int txbuff_size = dainviareHEX.Length / 2;

            SCardTransmit(hCard, ioRequest, txbuff, txbuff_size, (SCARD_IO_REQUEST)null, pbRecvBuffer, ref pcbRecvLength);

            string ris_hex = string.Empty;

            ris_hex = BitConverter.ToString(pbRecvBuffer).Replace("-", "");

            if (pcbRecvLength >= 2 && pcbRecvLength != 255)
            {
                if (ris_hex.Substring((pcbRecvLength * 2) - 4, 4) == "9000")
                {
                    uid = ris_hex.Substring(0, (pcbRecvLength * 2) - 4);
                    status = ris_hex.Substring((pcbRecvLength * 2) - 4, 4);
                    return true;
                }
                else
                {
                    uid = string.Empty;
                    status = ris_hex.Substring((pcbRecvLength * 2) - 4, 4);
                    return false;
                }
            }
            else
            {
                uid = string.Empty;
                status = "BUFFER DI RISPOSTA VUOTO";
                return false;
            }


        }

        public bool Restituisci__ATS_SL2(out string uid, out string status)
        {
            SCARD_IO_REQUEST ioRecv = new SCARD_IO_REQUEST();
            ioRecv.cbPciLength = 255;

            SCARD_IO_REQUEST ioRequest = new SCARD_IO_REQUEST();
            ioRequest.dwProtocol = (UInt32)PREFERRED_PROTOCOL.SCARD_PROTOCOL_T1;
            ioRequest.cbPciLength = 8;

            byte[] pbRecvBuffer = new byte[255];
            int pcbRecvLength = 255;

            string dainviareHEX = "3B8F8001804F0CA0000003060300390000000052";

            List<byte> txbuff_list = new List<byte>();
            for (int i = 0; i < dainviareHEX.Length - 1; i += 2)
            {
                txbuff_list.Add(Convert.ToByte(dainviareHEX.Substring(i, 2), 16));
            }
            int numero_elementi = txbuff_list.Count;
            byte[] txbuff = new byte[numero_elementi];
            for (int i = 0; i < numero_elementi; i++)
            {
                txbuff[i] = txbuff_list[i];
            }
            int txbuff_size = dainviareHEX.Length / 2;

            SCardTransmit(hCard, ioRequest, txbuff, txbuff_size, (SCARD_IO_REQUEST)null, pbRecvBuffer, ref pcbRecvLength);

            string ris_hex = string.Empty;

            ris_hex = BitConverter.ToString(pbRecvBuffer).Replace("-", "");

            if (pcbRecvLength >= 2 && pcbRecvLength != 255)
            {
                if (ris_hex.Substring((pcbRecvLength * 2) - 4, 4) == "9000")
                {
                    uid = ris_hex.Substring(0, (pcbRecvLength * 2) - 4);
                    status = ris_hex.Substring((pcbRecvLength * 2) - 4, 4);
                    return true;
                }
                else
                {
                    uid = string.Empty;
                    status = ris_hex.Substring((pcbRecvLength * 2) - 4, 4);
                    return false;
                }
            }
            else
            {
                uid = string.Empty;
                status = "BUFFER DI RISPOSTA VUOTO";
                return false;
            }


        }

        public bool ScriviDati(string indirizzo, string valori, out string status)
        {
            SCARD_IO_REQUEST ioRecv = new SCARD_IO_REQUEST();
            ioRecv.cbPciLength = 255;

            SCARD_IO_REQUEST ioRequest = new SCARD_IO_REQUEST();
            ioRequest.dwProtocol = (UInt32)PREFERRED_PROTOCOL.SCARD_PROTOCOL_T1;
            ioRequest.cbPciLength = 8;

            byte[] pbRecvBuffer = new byte[255];
            int pcbRecvLength = 255;

            int lunghezza=valori.Length/2;

            string lunhex=lunghezza.ToString("X").PadLeft(2,'0');

            string dainviareHEX = "80A8"+ indirizzo + lunhex + valori;

            List<byte> txbuff_list = new List<byte>();
            for (int i = 0; i < dainviareHEX.Length - 1; i += 2)
            {
                txbuff_list.Add(Convert.ToByte(dainviareHEX.Substring(i, 2), 16));
            }
            int numero_elementi = txbuff_list.Count;
            byte[] txbuff = new byte[numero_elementi];
            for (int i = 0; i < numero_elementi; i++)
            {
                txbuff[i] = txbuff_list[i];
            }
            int txbuff_size = dainviareHEX.Length / 2;

            SCardTransmit(hCard, ioRequest, txbuff, txbuff_size, (SCARD_IO_REQUEST)null, pbRecvBuffer, ref pcbRecvLength);

            string ris_hex = string.Empty;

            ris_hex = BitConverter.ToString(pbRecvBuffer).Replace("-", "");

            if (pcbRecvLength >= 2 && pcbRecvLength != 255)
            {
                if (ris_hex.Substring((pcbRecvLength * 2) - 4, 4) == "9000")
                {
                    status = ris_hex.Substring((pcbRecvLength * 2) - 4, 4);
                    return true;
                }
                else
                {
                    status = ris_hex.Substring((pcbRecvLength * 2) - 4, 4);
                    return false;
                }
            }
            else
            {
                status = "BUFFER DI RISPOSTA VUOTO";
                return false;
            }


        }

        public bool Commit__Switch_SL1(out string status)
        {
            SCARD_IO_REQUEST ioRecv = new SCARD_IO_REQUEST();
            ioRecv.cbPciLength = 255;

            SCARD_IO_REQUEST ioRequest = new SCARD_IO_REQUEST();
            ioRequest.dwProtocol = (UInt32)PREFERRED_PROTOCOL.SCARD_PROTOCOL_T1;
            ioRequest.cbPciLength = 8;

            byte[] pbRecvBuffer = new byte[255];
            int pcbRecvLength = 255;

            string dainviareHEX = "80AA000000";

            List<byte> txbuff_list = new List<byte>();
            for (int i = 0; i < dainviareHEX.Length - 1; i += 2)
            {
                txbuff_list.Add(Convert.ToByte(dainviareHEX.Substring(i, 2), 16));
            }
            int numero_elementi = txbuff_list.Count;
            byte[] txbuff = new byte[numero_elementi];
            for (int i = 0; i < numero_elementi; i++)
            {
                txbuff[i] = txbuff_list[i];
            }
            int txbuff_size = dainviareHEX.Length / 2;

            SCardTransmit(hCard, ioRequest, txbuff, txbuff_size, (SCARD_IO_REQUEST)null, pbRecvBuffer, ref pcbRecvLength);

            string ris_hex = string.Empty;

            ris_hex = BitConverter.ToString(pbRecvBuffer).Replace("-", "");

            if (pcbRecvLength >= 2 && pcbRecvLength != 255)
            {
                if (ris_hex.Substring((pcbRecvLength * 2) - 4, 4) == "9000")
                {
                    status = ris_hex.Substring((pcbRecvLength * 2) - 4, 4);
                    return true;
                }
                else
                {
                    status = ris_hex.Substring((pcbRecvLength * 2) - 4, 4);
                    return false;
                }
            }
            else
            {
                status = "BUFFER DI RISPOSTA VUOTO";
                return false;
            }


        }

        public bool AutenticazioneBlocco(string indirizzo, string chiave, out string status)
        {
            SCARD_IO_REQUEST ioRecv = new SCARD_IO_REQUEST();
            ioRecv.cbPciLength = 255;

            SCARD_IO_REQUEST ioRequest = new SCARD_IO_REQUEST();
            ioRequest.dwProtocol = (UInt32)PREFERRED_PROTOCOL.SCARD_PROTOCOL_T1;
            ioRequest.cbPciLength = 8;

            byte[] pbRecvBuffer = new byte[255];
            int pcbRecvLength = 255;


            int lunghezza = chiave.Length / 2;

            string lunhex = lunghezza.ToString("X").PadLeft(2, '0');

            string dainviareHEX = "FF820001" + lunhex + chiave;

            List<byte> txbuff_list = new List<byte>();
            for (int i = 0; i < dainviareHEX.Length - 1; i += 2)
            {
                txbuff_list.Add(Convert.ToByte(dainviareHEX.Substring(i, 2), 16));
            }
            int numero_elementi = txbuff_list.Count;
            byte[] txbuff = new byte[numero_elementi];
            for (int i = 0; i < numero_elementi; i++)
            {
                txbuff[i] = txbuff_list[i];
            }
            int txbuff_size = dainviareHEX.Length / 2;

            SCardTransmit(hCard, ioRequest, txbuff, txbuff_size, (SCARD_IO_REQUEST)null, pbRecvBuffer, ref pcbRecvLength);

            string ris_hex = string.Empty;

            ris_hex = BitConverter.ToString(pbRecvBuffer).Replace("-", "");

            if (pcbRecvLength >= 2 && pcbRecvLength != 255)
            {
                if (ris_hex.Substring((pcbRecvLength * 2) - 4, 4) == "9000")
                {
                    dainviareHEX = "FF8600000501"+indirizzo+"0001";

                    txbuff_list = new List<byte>();
                    for (int i = 0; i < dainviareHEX.Length - 1; i += 2)
                    {
                        txbuff_list.Add(Convert.ToByte(dainviareHEX.Substring(i, 2), 16));
                    }
                    numero_elementi = txbuff_list.Count;
                    txbuff = new byte[numero_elementi];
                    for (int i = 0; i < numero_elementi; i++)
                    {
                        txbuff[i] = txbuff_list[i];
                    }
                    txbuff_size = dainviareHEX.Length / 2;

                    SCardTransmit(hCard, ioRequest, txbuff, txbuff_size, (SCARD_IO_REQUEST)null, pbRecvBuffer, ref pcbRecvLength);

                    ris_hex = string.Empty;

                    ris_hex = BitConverter.ToString(pbRecvBuffer).Replace("-", "");

                    if (pcbRecvLength >= 2 && pcbRecvLength != 255)
                    {
                        if (ris_hex.Substring((pcbRecvLength * 2) - 4, 4) == "9000")
                        {
                            status = ris_hex.Substring((pcbRecvLength * 2) - 4, 4);
                            return true;
                        }
                        else
                        {
                            status = ris_hex.Substring((pcbRecvLength * 2) - 4, 4);
                            return false;
                        }
                    }
                    else
                    {
                        status = "BUFFER DI RISPOSTA VUOTO";
                        return false;
                    }
                }
                else
                {
                    status = ris_hex.Substring((pcbRecvLength * 2) - 4, 4);
                    return false;
                }
            }
            else
            {
                status = "BUFFER DI RISPOSTA VUOTO";
                return false;
            }


        }

        public bool Switch_SL2(string chiave, out string status)
        {
            SCARD_IO_REQUEST ioRecv = new SCARD_IO_REQUEST();
            ioRecv.cbPciLength = 255;

            SCARD_IO_REQUEST ioRequest = new SCARD_IO_REQUEST();
            ioRequest.dwProtocol = (UInt32)PREFERRED_PROTOCOL.SCARD_PROTOCOL_T1;
            ioRequest.cbPciLength = 8;

            byte[] pbRecvBuffer = new byte[255];
            int pcbRecvLength = 255;


            int lunghezza = chiave.Length / 2;

            string lunhex = lunghezza.ToString("X").PadLeft(2, '0');

            string dainviareHEX = "FF820001" + lunhex + chiave;

            List<byte> txbuff_list = new List<byte>();
            for (int i = 0; i < dainviareHEX.Length - 1; i += 2)
            {
                txbuff_list.Add(Convert.ToByte(dainviareHEX.Substring(i, 2), 16));
            }
            int numero_elementi = txbuff_list.Count;
            byte[] txbuff = new byte[numero_elementi];
            for (int i = 0; i < numero_elementi; i++)
            {
                txbuff[i] = txbuff_list[i];
            }
            int txbuff_size = dainviareHEX.Length / 2;

            SCardTransmit(hCard, ioRequest, txbuff, txbuff_size, (SCARD_IO_REQUEST)null, pbRecvBuffer, ref pcbRecvLength);

            string ris_hex = string.Empty;

            ris_hex = BitConverter.ToString(pbRecvBuffer).Replace("-", "");

            if (pcbRecvLength >= 2 && pcbRecvLength != 255)
            {
                if (ris_hex.Substring((pcbRecvLength * 2) - 4, 4) == "9000")
                {
                    dainviareHEX = "FF8600000501" + "9002" + "0001";

                    txbuff_list = new List<byte>();
                    for (int i = 0; i < dainviareHEX.Length - 1; i += 2)
                    {
                        txbuff_list.Add(Convert.ToByte(dainviareHEX.Substring(i, 2), 16));
                    }
                    numero_elementi = txbuff_list.Count;
                    txbuff = new byte[numero_elementi];
                    for (int i = 0; i < numero_elementi; i++)
                    {
                        txbuff[i] = txbuff_list[i];
                    }
                    txbuff_size = dainviareHEX.Length / 2;

                    SCardTransmit(hCard, ioRequest, txbuff, txbuff_size, (SCARD_IO_REQUEST)null, pbRecvBuffer, ref pcbRecvLength);

                    ris_hex = string.Empty;

                    ris_hex = BitConverter.ToString(pbRecvBuffer).Replace("-", "");

                    if (pcbRecvLength >= 2 && pcbRecvLength != 255)
                    {
                        if (ris_hex.Substring((pcbRecvLength * 2) - 4, 4) == "9000")
                        {
                            status = ris_hex.Substring((pcbRecvLength * 2) - 4, 4);
                            return true;
                        }
                        else
                        {
                            status = ris_hex.Substring((pcbRecvLength * 2) - 4, 4);
                            return false;
                        }
                    }
                    else
                    {
                        status = "BUFFER DI RISPOSTA VUOTO";
                        return false;
                    }
                }
                else
                {
                    status = ris_hex.Substring((pcbRecvLength * 2) - 4, 4);
                    return false;
                }
            }
            else
            {
                status = "BUFFER DI RISPOSTA VUOTO";
                return false;
            }


        }

        public bool Switch_SL3(string chiave, out string status)
        {
            SCARD_IO_REQUEST ioRecv = new SCARD_IO_REQUEST();
            ioRecv.cbPciLength = 255;

            SCARD_IO_REQUEST ioRequest = new SCARD_IO_REQUEST();
            ioRequest.dwProtocol = (UInt32)PREFERRED_PROTOCOL.SCARD_PROTOCOL_T1;
            ioRequest.cbPciLength = 8;

            byte[] pbRecvBuffer = new byte[255];
            int pcbRecvLength = 255;


            int lunghezza = chiave.Length / 2;

            string lunhex = lunghezza.ToString("X").PadLeft(2, '0');

            string dainviareHEX = "FF820001" + lunhex + chiave;

            List<byte> txbuff_list = new List<byte>();
            for (int i = 0; i < dainviareHEX.Length - 1; i += 2)
            {
                txbuff_list.Add(Convert.ToByte(dainviareHEX.Substring(i, 2), 16));
            }
            int numero_elementi = txbuff_list.Count;
            byte[] txbuff = new byte[numero_elementi];
            for (int i = 0; i < numero_elementi; i++)
            {
                txbuff[i] = txbuff_list[i];
            }
            int txbuff_size = dainviareHEX.Length / 2;

            SCardTransmit(hCard, ioRequest, txbuff, txbuff_size, (SCARD_IO_REQUEST)null, pbRecvBuffer, ref pcbRecvLength);

            string ris_hex = string.Empty;

            ris_hex = BitConverter.ToString(pbRecvBuffer).Replace("-", "");

            if (pcbRecvLength >= 2 && pcbRecvLength != 255)
            {
                if (ris_hex.Substring((pcbRecvLength * 2) - 4, 4) == "9000")
                {
                    dainviareHEX = "FF8600000501" + "9003" + "0001";

                    txbuff_list = new List<byte>();
                    for (int i = 0; i < dainviareHEX.Length - 1; i += 2)
                    {
                        txbuff_list.Add(Convert.ToByte(dainviareHEX.Substring(i, 2), 16));
                    }
                    numero_elementi = txbuff_list.Count;
                    txbuff = new byte[numero_elementi];
                    for (int i = 0; i < numero_elementi; i++)
                    {
                        txbuff[i] = txbuff_list[i];
                    }
                    txbuff_size = dainviareHEX.Length / 2;

                    SCardTransmit(hCard, ioRequest, txbuff, txbuff_size, (SCARD_IO_REQUEST)null, pbRecvBuffer, ref pcbRecvLength);

                    ris_hex = string.Empty;

                    ris_hex = BitConverter.ToString(pbRecvBuffer).Replace("-", "");

                    if (pcbRecvLength >= 2 && pcbRecvLength != 255)
                    {
                        if (ris_hex.Substring((pcbRecvLength * 2) - 4, 4) == "9000")
                        {
                            status = ris_hex.Substring((pcbRecvLength * 2) - 4, 4);
                            return true;
                        }
                        else
                        {
                            status = ris_hex.Substring((pcbRecvLength * 2) - 4, 4);
                            return false;
                        }
                    }
                    else
                    {
                        status = "BUFFER DI RISPOSTA VUOTO";
                        return false;
                    }
                }
                else
                {
                    status = ris_hex.Substring((pcbRecvLength * 2) - 4, 4);
                    return false;
                }
            }
            else
            {
                status = "BUFFER DI RISPOSTA VUOTO";
                return false;
            }


        }

        public bool AggiornaDati(string indirizzo, string valori, out string status)
        {
            SCARD_IO_REQUEST ioRecv = new SCARD_IO_REQUEST();
            ioRecv.cbPciLength = 255;

            SCARD_IO_REQUEST ioRequest = new SCARD_IO_REQUEST();
            ioRequest.dwProtocol = (UInt32)PREFERRED_PROTOCOL.SCARD_PROTOCOL_T1;
            ioRequest.cbPciLength = 8;

            byte[] pbRecvBuffer = new byte[255];
            int pcbRecvLength = 255;

            int lunghezza = valori.Length / 2;

            string lunhex = lunghezza.ToString("X").PadLeft(2, '0');

            string dainviareHEX = "FFD6" + indirizzo + lunhex + valori;

            List<byte> txbuff_list = new List<byte>();
            for (int i = 0; i < dainviareHEX.Length - 1; i += 2)
            {
                txbuff_list.Add(Convert.ToByte(dainviareHEX.Substring(i, 2), 16));
            }
            int numero_elementi = txbuff_list.Count;
            byte[] txbuff = new byte[numero_elementi];
            for (int i = 0; i < numero_elementi; i++)
            {
                txbuff[i] = txbuff_list[i];
            }
            int txbuff_size = dainviareHEX.Length / 2;

            SCardTransmit(hCard, ioRequest, txbuff, txbuff_size, (SCARD_IO_REQUEST)null, pbRecvBuffer, ref pcbRecvLength);

            string ris_hex = string.Empty;

            ris_hex = BitConverter.ToString(pbRecvBuffer).Replace("-", "");

            if (pcbRecvLength >= 2 && pcbRecvLength != 255)
            {
                if (ris_hex.Substring((pcbRecvLength * 2) - 4, 4) == "9000")
                {
                    status = ris_hex.Substring((pcbRecvLength * 2) - 4, 4);
                    return true;
                }
                else
                {
                    status = ris_hex.Substring((pcbRecvLength * 2) - 4, 4);
                    return false;
                }
            }
            else
            {
                status = "BUFFER DI RISPOSTA VUOTO";
                return false;
            }


        }

        public bool LeggiDati(string indirizzo, out string dati, out string status)
        {
            SCARD_IO_REQUEST ioRecv = new SCARD_IO_REQUEST();
            ioRecv.cbPciLength = 255;

            SCARD_IO_REQUEST ioRequest = new SCARD_IO_REQUEST();
            ioRequest.dwProtocol = (UInt32)PREFERRED_PROTOCOL.SCARD_PROTOCOL_T1;
            ioRequest.cbPciLength = 8;

            byte[] pbRecvBuffer = new byte[255];
            int pcbRecvLength = 255;

            string dainviareHEX = "FFB0" + indirizzo + "00";

            List<byte> txbuff_list = new List<byte>();
            for (int i = 0; i < dainviareHEX.Length - 1; i += 2)
            {
                txbuff_list.Add(Convert.ToByte(dainviareHEX.Substring(i, 2), 16));
            }
            int numero_elementi = txbuff_list.Count;
            byte[] txbuff = new byte[numero_elementi];
            for (int i = 0; i < numero_elementi; i++)
            {
                txbuff[i] = txbuff_list[i];
            }
            int txbuff_size = dainviareHEX.Length / 2;

            SCardTransmit(hCard, ioRequest, txbuff, txbuff_size, (SCARD_IO_REQUEST)null, pbRecvBuffer, ref pcbRecvLength);

            string ris_hex = string.Empty;

            ris_hex = BitConverter.ToString(pbRecvBuffer).Replace("-", "");

            if (pcbRecvLength >= 2 && pcbRecvLength != 255)
            {
                if (ris_hex.Substring((pcbRecvLength * 2) - 4, 4) == "9000")
                {
                    status = ris_hex.Substring((pcbRecvLength * 2) - 4, 4);
                    dati = ris_hex.Substring(0, (pcbRecvLength * 2) - 4);
                    return true;
                }
                else
                {
                    status = ris_hex.Substring((pcbRecvLength * 2) - 4, 4);
                    dati = string.Empty;
                    return false;
                }
            }
            else
            {
                status = "BUFFER DI RISPOSTA VUOTO";
                dati = string.Empty;
                return false;
            }


        }
    }
}
