using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Security.Cryptography;
using System.Text.RegularExpressions;


namespace AVA_SERVER
{

    public partial class AVASERVER : Form
    {
        #region AllStruct
        class Client_Player
        {
            public string Game_User;
            public byte[] Game_Key;
            public string Game_Server;
            public int Game_Version;
            public string Token;
            public int ErrorCode;
        }
        class ClientKeyAreA
        {
            public int ClientKey1;
            public int ClientKey2;
            public int ServerKey1;
            public int ServerKey2;
            public byte[] PublicKeyA;

        }
        #endregion
        #region Global
        //服务端Sokcet
        Socket Tcp_Ser;
        //开关
        bool IsStart;
        //服务链接成员表
        static List<Socket> Client_Sock = new List<Socket>();
        //用户数据
        static List<Client_Player> Client_Play = new List<Client_Player>();
        //客户端密钥配置
        ClientKeyAreA ClientKeyConf = new ClientKeyAreA();
        #endregion


        public AVASERVER()
        {
            InitializeComponent();
        }

        private void AVASERVER_Load(object sender, EventArgs e)
        {
            //for (int i = 0; i < 999; i++)
            //{
            //    byte[] Aeskey = new byte[0];
            //    string Token = InitServerAESKey(ref Aeskey);
            //    Console.WriteLine(Token);
            //    Console.WriteLine(BitConverter.ToString(Aeskey));
            //}

            //MessageBox.Show("Welcome","欢迎");
        }

        private void StartServer_Click(object sender, EventArgs e)
        {
            if (StartServer.Text == "Start")
            {
                #region 开启服务端口
                int Port;
                try
                {
                    Port = Convert.ToInt32(ServerPort.Text);
                }
                catch (Exception)
                {
                    MessageBox.Show("Port Fail\n端口非法,请检查正确再试！", "Error_Tips");
                    return;
                }
                if (Port <= 0)
                {
                    MessageBox.Show("Port Error\n端口错误,请确保正常再试！", "Error_Tips");
                    return;
                }
                try
                {
                    IPEndPoint LocalEp = new IPEndPoint(IPAddress.Any, Port);
                    Tcp_Ser = new Socket(LocalEp.Address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                    Tcp_Ser.Bind(LocalEp);//绑定
                    Tcp_Ser.Listen(0);//无限制
                }
                catch (Exception)
                {

                }
                #endregion
                #region Recv_Client_Sock_Thread  接受用户端口线程
                for (int i = 0; i < 1; i++)
                {
                    Thread Recv_Thr = new Thread(Recv_Client);
                    Recv_Thr.IsBackground = false;
                    Recv_Thr.Start(); //开启线程循环接受
                }
                #endregion
                IsStart = true;
                StartServer.Text = "Stop";
            }
            else
            {
                try
                {
                    Tcp_Ser.Dispose();
                    Tcp_Ser.Close();
                }
                catch (Exception)
                {
                    MessageBox.Show("服务停止时出现错误");
                }
                IsStart = false;
                StartServer.Text = "Start";

            }

        }

        void Recv_Client()//用于引入客户跟数据至数组
        {
            while (IsStart == true)
            {
                //该线程只管接受客户
                //通过链表顺序排放进入客户
                Thread.Sleep(100);//防止造成线程阻塞
                try
                {
                    Socket Tcpr = Tcp_Ser.Accept();
                    //200毫秒内等待//
                    if (Tcpr.Connected == false || Tcpr.Poll(1000 * 1000, SelectMode.SelectWrite) == false)
                    {
                        Tcpr.Close();
                        continue;
                    }
                    Client_Sock.Add(Tcpr);
                    #region Recv_Manage_Client_Data_Thread  管理副线程返回的用户端口,进行数据整理
                    Thread Recv_Thr = new Thread(new ThreadStart(() => Recv_Client_Data(Tcpr)));
                    Recv_Thr.IsBackground = false;
                    Recv_Thr.Start(); //开启线程循环接受
                    #endregion
                }
                catch (Exception)
                {
                    Log("Socket Failed");
                }

            }
        }
        void Recv_Client_Data(Socket Thread_Client)//存放的客户序列 
        {   //该线程只负责接受客户数据
            byte[] buff = new byte[0x4000];
            int retLen = 0, Len = 0x4000;
            Client_Player User_Info = new Client_Player();
            Client_Play.Add(User_Info);
            while (IsStart == true)
            {
                Thread.Sleep(100);
                try
                {
                    retLen = Thread_Client.Receive(buff, Len, SocketFlags.None);
                    if (retLen == 0)
                    {
                        Log("Receive_Client_Exit_From_DataLen");
                        break;
                    }

                }
                catch (Exception)
                {
                    Log("Receive_Client_Exit_From_Except");
                    break;
                }
                int Pack_Len = 0;
                int XuLie = 0;
                byte[] Client_Data;
                while (retLen > 0)
                {
                    Pack_Len = BitConverter.ToInt32(buff, XuLie);
                    if (retLen >= Pack_Len)
                    {
                        Client_Data = new byte[Pack_Len + 10];
                        Array.Copy(buff, 0, Client_Data, 0, Pack_Len + 10);
                        Log("PackLen:" + Pack_Len);
                        Log("Pack:" + To_HexStrFormByte(Client_Data));

                        Match_Game_Pack(Thread_Client, Client_Data, ref User_Info);

                        Pack_Len = Pack_Len + 10;
                        XuLie += Pack_Len;
                        retLen = retLen - Pack_Len;
                    }
                    else
                    {
                        break;
                    }
                }
            }
            try
            {
                Thread_Client.Close();
            }
            catch (Exception)
            {

            }
            Client_Sock.Remove(Thread_Client);
            Client_Play.Remove(User_Info);
        }
        void Match_Game_Pack(Socket Client,Byte[] Data,ref Client_Player UserInfo)
        {
            byte[] MiData = new byte[Data.Length - 10];
            Array.Copy(Data, 10, MiData, 0, MiData.Length);
            switch (Data[4])
            {
                case 1:
                    {
                        UserInfo.Game_Key = new byte[] { 0x32, 0x33, 0x31, 0x37, 0x11, 0x14, 0x19, 0xF1, 0xA2, 0xE1, 0xBE, 0x7A, 0x10, 0x4F, 0x14, 0x0A };
                        UserInfo.Game_Version = 478428;
                        break;
                    }
            }
            MiData = AES_Decrypt(MiData, UserInfo.Game_Key);
            Log("MinPack:" + To_HexStrFormByte(MiData));
            switch (MiData[4])
            {
                case 1:
                    {
                        int i = 20;
                        int Game_UserLen  = BitConverter.ToInt32(MiData, i);
                        i += 4;
                        UserInfo.Game_User = Encoding.Unicode.GetString(MiData, i, Game_UserLen - 2);
                        Log(UserInfo.Game_User);
                        i += Game_UserLen;
                        #region 更换AES密钥
                        byte[] LinKey = new byte[0];
                        byte[] Token = Encoding.Default.GetBytes(InitServerAESKey(ref LinKey));
                        Log(BitConverter.ToString(LinKey));
                        byte[] RetData = Token;
                        RetData = BYTE_ADD(BitConverter.GetBytes(RetData.Length), RetData);
                        RetData = BYTE_ADD(BYTE_ADD(Encoding.Default.GetBytes("GATE51"), new byte[] { 0, 0 }), RetData);
                        RetData = BYTE_ADD(BYTE_ADD(BitConverter.GetBytes(0x7A04DD3D), new byte[] { 0 }), RetData);
                        RetData = BYTE_ADD(new byte[6] { 0, 0, 1, 0, 0, 0 }, RetData);
                        RetData = AES_Encrypt(RetData, UserInfo.Game_Key);
                        RetData = BYTE_ADD(BYTE_ADD(BitConverter.GetBytes(RetData.Length), new byte[] { 2, 0, 0, 0, 0, 0 }), RetData);
                        Protect_Send(Client, RetData);
                        UserInfo.Game_Key = LinKey;
                        #endregion
                        break;
                    }
                case 3:
                    {
                        int i = 11;
                        UserInfo.Game_Server = Encoding.Default.GetString(MiData, i,6);
                        byte[] RetData = BitConverter.GetBytes(0);//FF0065为拒绝链接
                        RetData = BYTE_ADD(RetData, new byte[] { 0 });
                        RetData = BYTE_ADD(RetData, Encoding.Default.GetBytes(UserInfo.Game_Server));
                        RetData = BYTE_ADD(RetData, BitConverter.GetBytes(0));
                        RetData = AES_Encrypt(RetData, UserInfo.Game_Key);
                        RetData = BYTE_ADD(BYTE_ADD(BitConverter.GetBytes(RetData.Length), new byte[] { 4, 0, 0, 0, 0, 0 }), RetData);
                        Protect_Send(Client, RetData);
                        break;
                    }
                case 16:
                    {
                        byte[] Mi2Data = new byte[MiData.Length - 0x12];
                        Array.Copy(MiData, 0x12, Mi2Data, 0, Mi2Data.Length);
                        int i = 0;
                        int DataLen = BitConverter.ToInt32(Mi2Data,i);
                        i += 4;
                        i += 2;//Len  Short
                        i += 2;//Short
                        int PackSef = BitConverter.ToInt16(Mi2Data, i);//标识
                        i += 2;
                        switch (PackSef)
                        {
                            case 0x701://首次登录
                                {
                                    int ClientVersion = BitConverter.ToInt32(Mi2Data, i);//版本
                                    i += 4;
                                    if (ClientVersion == UserInfo.Game_Version)
                                    {
                                        i += 4;//7FFFFFFF
                                        i += 4;//37
                                        i += 1;
                                        i += 0x10;
                                        string LodingInfo = Encoding.Unicode.GetString(Mi2Data, i, DataLen - i);
                                        //"1|111111111111111|0|222222222222222|_|funtown$AVA" 账号 密码  标识
                                        string[] Lodinfo =   LodingInfo.Split('|');
                                        byte[] RetBuff = BitConverter.GetBytes(0);
                                        RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes(0x749));//标识
                                        RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes(0x97));
                                        RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes((short)0x97));
                                        RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes((short)0x91));
                                        RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes((short)0x749));//标识
                                        if (Lodinfo.Count() == 6)
                                        {
                                            if (Lodinfo[0] == "1" && Lodinfo[2] == "0" && Lodinfo[4] == "_" && Lodinfo[5] == "funtown$AVA")
                                            {

                                                if (Lodinfo[1] == "admin" && Lodinfo[3] == "admin")
                                                {
                                                    Random Rand = new Random();
                                                    string LodingToken = Rand.Next(256, 65535).ToString("X4");
                                                    for (int j = 0; j < 7; j++)
                                                    {
                                                        LodingToken += Rand.Next(256, 65535).ToString("X4");
                                                    }
                                                    RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes(0x010100));
                                                    RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes(0x41F4DE));
                                                    RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes(0));
                                                    RetBuff = BYTE_ADD(RetBuff, new byte[] { 0x7A});
                                                    RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes(LodingToken.Length));
                                                    RetBuff = BYTE_ADD(RetBuff, Encoding.Unicode.GetBytes(LodingToken));
                                                    RetBuff = BYTE_ADD(RetBuff, new byte[140 - LodingToken.Length * 2]);
                                                    UserInfo.Token = LodingToken;
                                                    Log("Return_Loding_Data - " + LodingToken);
                                                }
                                                else
                                                {
                                                    UserInfo.ErrorCode = 0x33C4;
                                                    RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes(0xC3500186));
                                                    RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes(0));
                                                    RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes(0));
                                                    RetBuff = BYTE_ADD(RetBuff,BitConverter.GetBytes(UserInfo.ErrorCode));
                                                    RetBuff = BYTE_ADD(RetBuff, new byte[141]);
                                                    Log("Return_Loding_Error Code- " + UserInfo.ErrorCode);
                                                }
                                                RetBuff = AES_Encrypt(RetBuff, UserInfo.Game_Key);
                                                RetBuff = BYTE_ADD(BYTE_ADD(BitConverter.GetBytes(RetBuff.Length), new byte[] { 16, 0, 0, 0, 0, 0 }), RetBuff);
                                                Protect_Send(Client, RetBuff);
                                                if (UserInfo.Token != null)
                                                {
                                                    Loginstatus(Client, ref UserInfo);
                                                }
                                            }
                                        }
                                        
                                    }
                                    break;
                                }
                            case 0x748://二次登录
                                {
                                    int ThisErrorCode = BitConverter.ToInt32(Mi2Data, i);//错误码
                                    i += 4;
                                    if (ThisErrorCode == UserInfo.ErrorCode && UserInfo.ErrorCode != 0)
                                    {
                                        i += 9;
                                        string LodUsr = Encoding.Unicode.GetString(Mi2Data, i, 15 * 2);
                                        if (LodUsr.IndexOf('\0') > 0)
                                        {
                                            LodUsr = LodUsr.Substring(0, LodUsr.IndexOf('\0'));
                                        }
                                        i += 32;
                                        string LodPsw = Encoding.Unicode.GetString(Mi2Data, i, 15 * 2);
                                        if (LodPsw.IndexOf('\0') > 0)
                                        {
                                            LodPsw = LodPsw.Substring(0, LodPsw.IndexOf('\0'));
                                        }
                                        i += 32;
                                        Random Rand = new Random();
                                        byte[] RetBuff = BitConverter.GetBytes(0);
                                        RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes(0x749));//标识
                                        RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes(0x97));
                                        RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes((short)0x97));
                                        RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes((short)0x91));
                                        RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes((short)0x749));//标识
                                        if (LodUsr == "admin" && LodPsw == "admin")
                                        {
                                            string LodingToken = Rand.Next(256, 65535).ToString("X4");
                                            for (int j = 0; j < 7; j++)
                                            {
                                                LodingToken += Rand.Next(256, 65535).ToString("X4");
                                            }
                                            RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes(0x010100));
                                            RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes(0x41F4DE));
                                            RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes(0));
                                            RetBuff = BYTE_ADD(RetBuff, new byte[] { 0x7A });
                                            RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes(LodingToken.Length));
                                            RetBuff = BYTE_ADD(RetBuff, Encoding.Unicode.GetBytes(LodingToken));
                                            RetBuff = BYTE_ADD(RetBuff, new byte[140 - LodingToken.Length * 2]);
                                            UserInfo.Token = LodingToken;
                                            Log("Return_Loding_Data - " + LodingToken);
                                        }
                                        else
                                        {
                                            UserInfo.ErrorCode = Rand.Next(256, 65535);
                                            RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes(0xC3500186));
                                            RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes(0));
                                            RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes(0));
                                            RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes(UserInfo.ErrorCode));
                                            RetBuff = BYTE_ADD(RetBuff, new byte[141]);
                                            Log("Return_Loding_Error Code- " + UserInfo.ErrorCode);
                                        }
                                        RetBuff = AES_Encrypt(RetBuff, UserInfo.Game_Key);
                                        RetBuff = BYTE_ADD(BYTE_ADD(BitConverter.GetBytes(RetBuff.Length), new byte[] { 16, 0, 0, 0, 0, 0 }), RetBuff);
                                        Protect_Send(Client, RetBuff);
                                        if (UserInfo.Token !=null)
                                        {
                                            Loginstatus(Client, ref UserInfo);
                                        }
                                    }
                                    break;
                                }
                        }
                        break;
                    }
            }

        }
        #region Pack
        void Loginstatus(Socket Client,ref Client_Player UserInfo)
        {
            byte[] RetBuff = BitConverter.GetBytes(0);
            RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes(0x702));//标识
            RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes(0x30));//标识
            RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes((short)0x30));
            RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes((short)0x2A));
            RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes((short)0x702));//标识
            RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes(0x65A1300));
            RetBuff = BYTE_ADD(RetBuff, BitConverter.GetBytes((short)0x0));
            RetBuff = BYTE_ADD(RetBuff, Encoding.Default.GetBytes(UserInfo.Game_Server));
            RetBuff = BYTE_ADD(RetBuff, new byte[0x26]);
            RetBuff = AES_Encrypt(RetBuff, UserInfo.Game_Key);
            RetBuff = BYTE_ADD(BYTE_ADD(BitConverter.GetBytes(RetBuff.Length), new byte[] { 16, 0, 0, 0, 0, 0 }), RetBuff);
            Protect_Send(Client, RetBuff);
            Log("Return_Loding_Server - Ok");
        }
        #endregion
        #region InitGameAesKey
        string InitServerAESKey(ref byte[] AesKey)
        {
            string ResultStr;
            AesKey = new byte[0x10];
            Random Rand = new Random();
            ClientKeyConf.ClientKey1 = 0x51CC923;
            ClientKeyConf.ClientKey2 = 0x51C7DE8;
            //ClientKeyConf.ServerKey1 = 0x12DF25F;
            // GetGamePublicKey(ClientKeyConf.ServerKey1, ClientKeyConf.ClientKey2, ref ClientKeyConf.PublicKeyA);
            do
            {
                do
                {
                    //通过随机匹配获取一个能够效验的公秘钥匙
                    ClientKeyConf.ServerKey1 = Rand.Next(0x1000000, 0x2000000);
                } while (InitPublicKey(ClientKeyConf.ServerKey1, ClientKeyConf.ClientKey2));
                GetGamePublicKey(ClientKeyConf.ServerKey1, ClientKeyConf.ClientKey2, ref ClientKeyConf.PublicKeyA);
                //如果密钥三处值等于服务生成密钥
                if (BitConverter.ToInt32(ClientKeyConf.PublicKeyA, 8) == ClientKeyConf.ServerKey1)
                {
                    ClientKeyConf.ServerKey2 = BitConverter.ToInt32(ClientKeyConf.PublicKeyA, 12);
                    break;
                }
                //如果密钥一处值等于客户端固定密钥
                else if (BitConverter.ToInt32(ClientKeyConf.PublicKeyA, 0) == ClientKeyConf.ClientKey2)
                {
                    ClientKeyConf.ServerKey2 = BitConverter.ToInt32(ClientKeyConf.PublicKeyA, 4);
                    break;
                }
                //如果密钥都不相同设定为负一值
            } while (true);
            //Log(ClientKeyConf.ServerKey1.ToString("X8"));
            //Log(ClientKeyConf.ServerKey2.ToString("X8"));
            ResultStr = ClientKeyConf.ServerKey1.ToString("X8");
            int ServerDataLen = 8;//8段数据
            for (int i = 0; i < ServerDataLen; i++)
            {
                int RandC;
                int result;
                do
                {
                    RandC = Rand.Next(0x2000000, 0x4000000);
                    result = GetServerNewEncKey(RandC, ClientKeyConf.ServerKey2, ClientKeyConf.ClientKey1);
                } while (result > 65536 || result < 256);
                Array.Copy(BitConverter.GetBytes(result), 0, AesKey, i * 2, 2);
                ResultStr+=RandC.ToString("X8");

            }
            return ResultStr;
        }
        //此处服务密钥为随机生成//客户密钥为固定密钥2//返回一个对称 服务/客户 密钥//存放在公秘数组内//
        bool InitPublicKey(int InitServerKey,int ClientKey)
        {
            bool Result;
            try
            {
                if (InitServerKey == 0)
                {
                    return true;
                }
                int Lin_C = ClientKey / InitServerKey;
                int Scrt = ClientKey - InitServerKey * Lin_C;
                if (Scrt == 1)
                {
                    return false;
                }
                Result = InitPublicKey(Scrt, InitServerKey);
            }
            catch (Exception)
            {
                Result = true;
            }
            return Result;
        }
        int GetGamePublicKey(int ServerKey,int ClientKey ,ref byte[] PublicKey)
        {
            //try
            //{
                PublicKey = new byte[0x14];
                int Lin_C = ClientKey / ServerKey;
                int Scrt = ClientKey - ServerKey * Lin_C;
                if (Scrt == 1)
                {
                    Array.Copy(BitConverter.GetBytes(ServerKey), 0, PublicKey, 0, 4);
                    Array.Copy(BitConverter.GetBytes(Lin_C), 0, PublicKey, 4, 4);
                    Array.Copy(BitConverter.GetBytes(ClientKey), 0, PublicKey, 8, 4);
                    Array.Copy(BitConverter.GetBytes(1), 0, PublicKey, 12, 4);
                    Array.Copy(BitConverter.GetBytes(1), 0, PublicKey, 16, 4);
                    return 1;
                }
                int Result = GetGamePublicKey(Scrt, ServerKey, ref PublicKey);
                if (Result == -1)
                {
                    return -1;
                }
                if (Result == 1)
                {
                    Array.Copy(BitConverter.GetBytes(ClientKey), 0, PublicKey, 0, 4);
                    Array.Copy(BitConverter.GetBytes(ServerKey), 0, PublicKey, 8, 4);
                    Array.Copy(BitConverter.GetBytes(BitConverter.ToInt32(PublicKey, 12) + Lin_C * BitConverter.ToInt32(PublicKey, 4)), 0, PublicKey, 12, 4);
                }
                else
                {
                    Array.Copy(BitConverter.GetBytes(BitConverter.ToInt32(PublicKey, 4) + Lin_C * BitConverter.ToInt32(PublicKey, 12)), 0, PublicKey, 4, 4);
                    Array.Copy(BitConverter.GetBytes(ClientKey), 0, PublicKey, 8, 4);
                }
                return 1 - Result;
            //}
            //catch (Exception)
            //{
            //    return -1;
            //}
            
        }
        //此处使用的服务密钥 为服务公钥// 客户密钥 为固定密钥1// 生成Key为随机//如果算法可行则生成并存储
        int GetServerNewEncKey(long InitKey, int ServerKey,long ClientKey)
        {
            if (ServerKey == 0)
            {
                return 1;
            }
            long Lin_C = 1;
            long Initk = InitKey;
            int Serverk = ServerKey;
            int f = 0;
            while (true)
            {
                if (Serverk % 2 == 1)
                {
                    Lin_C *= Initk;
                    f = 0;
                    if (Lin_C < 0)
                    {
                        f = 1;
                        Lin_C = -Lin_C;
                    }
                    if (ClientKey < 0)
                    {
                        ClientKey = -ClientKey;
                    }
                    if (ClientKey == (int)ClientKey)
                    {
                        Lin_C %=ClientKey;
                    }
                    if (f - 1 == 0)
                    {
                        Lin_C = -Lin_C;
                    }
                }
                Initk *= Initk;
                f = 0;
                if (InitKey < 0)
                {
                    f = 1;
                    InitKey = -InitKey;
                }
                if (ClientKey < 0)
                {
                    ClientKey = -ClientKey;
                }
                if (ClientKey == (int)ClientKey)
                {
                    Initk %= ClientKey;
                }
                if (f - 1 == 0)
                {
                    Initk = -Initk;
                }
                Serverk >>= 1;
                if (Serverk <= 0)
                {
                    break;
                }
            }
            return (int)Lin_C;
        }
        #endregion
        #region AES
        byte[] AES_Encrypt(byte[] Data, byte[] Key)
        {
            Aes Aes_ = Aes.Create();
            Aes_.Key = Key;
            Aes_.Mode = CipherMode.ECB;
            Aes_.Padding = PaddingMode.Zeros;
            ICryptoTransform AES_Encrypt =  Aes_.CreateEncryptor();
            byte[] Result = AES_Encrypt.TransformFinalBlock(Data, 0, Data.Length);
            AES_Encrypt.Dispose();
            Aes_.Clear();
            return Result;
        }
        byte[] AES_Decrypt(byte[] Data, byte[] Key)
        {
            Aes Aes_ = Aes.Create();
            Aes_.Key = Key;
            Aes_.Mode = CipherMode.ECB;
            Aes_.Padding = PaddingMode.Zeros;
            ICryptoTransform AES_Decrypt = Aes_.CreateDecryptor();
            byte[] Result = AES_Decrypt.TransformFinalBlock(Data, 0, Data.Length);
            AES_Decrypt.Dispose();
            Aes_.Clear();
            return Result;
        }
        #endregion

        void Protect_Send(Socket Client,byte[]Data)
        {
            try
            {
                Client.Send(Data);
            }
            catch (Exception)
            {
                Log("Send Error");
            }
        }
        byte[] BYTE_ADD(byte[] A, byte[] B)
        {
            byte[] C = new byte[A.Length + B.Length];
            A.CopyTo(C, 0);
            B.CopyTo(C, A.Length);
            return C;
        }
        string To_HexStrFormByte(Byte[] ByteData)
        {
            string Hex = "";
            for (int i = 0; i < ByteData.Length; i++)
            {
                Hex += string.Format("{0:X2}", ByteData[i]);
            }
            return Hex;
        }
        byte[] HexStringToByte(string hs)
        {
            string strTemp = "";
            byte[] b = new byte[hs.Length / 2];
            for (int i = 0; i < hs.Length / 2; i++)
            {
                strTemp = hs.Substring(i * 2, 2);
                b[i] = Convert.ToByte(strTemp, 16);
            }
            return b;
        }
        void Log(string c)
        {
            Console.WriteLine(c);
        }


    }
}
