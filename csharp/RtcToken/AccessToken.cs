using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace RtcToken
{
    using Description = DescriptionAttribute;

    public class ByteArrayReader
    {
        private BinaryReader cin;

        public ByteArrayReader(byte[] a)
        {
            cin = new BinaryReader(new MemoryStream(a));
        }

        public short ReadShort()
        {
            return cin.ReadInt16();
        }


        public int ReadInt()
        {
            return cin.ReadInt32();
        }

        public byte[] ReadBytes()
        {
            short length = ReadShort();
            return cin.ReadBytes(length);
        }

        public string ReadString()
        {
            byte[] bytes = ReadBytes();
            return Encoding.UTF8.GetString(bytes);
        }

        public Dictionary<short, string> ReadStringMap()
        {
            Dictionary<short, string> map = new Dictionary<short, string>();
            short length = ReadShort();

            for (short i = 0; i < length; ++i)
            {
                short k = ReadShort();
                string v = ReadString();
                map.Add(k, v);
            }

            return map;
        }

        public SortedDictionary<short, int> ReadIntMap()
        {
            SortedDictionary<short, int> map = new SortedDictionary<short, int>();

            short length = ReadShort();

            for (short i = 0; i < length; ++i)
            {
                short k = ReadShort();
                int v = ReadInt();
                map.Add(k, v);
            }

            return map;
        }
    }

    public class ByteArrayWriter
    {
        MemoryStream buf;
        private BinaryWriter cout;

        public ByteArrayWriter()
        {
            buf = new MemoryStream();
            cout = new BinaryWriter(buf);
        }

        public byte[] AsBytes()
        {
            cout.Close();
            return buf.ToArray();
        }

        // packUint16
        public ByteArrayWriter Put(short v)
        {
            cout.Write(v);
            return this;
        }

        public ByteArrayWriter Put(byte[] v)
        {
            Put((short) v.Length);
            cout.Write(v);
            return this;
        }

        // packUint32
        public ByteArrayWriter Put(int v)
        {
            cout.Write(v);
            return this;
        }

        public ByteArrayWriter Put(long v)
        {
            cout.Write(v);
            return this;
        }

        public ByteArrayWriter Put(string v)
        {
            return Put(Encoding.UTF8.GetBytes(v));
        }

        public ByteArrayWriter Put(Dictionary<short, string> extra)
        {
            Put((short) extra.Count);

            foreach (var pair in extra)
            {
                Put(pair.Key);
                Put(pair.Value);
            }

            return this;
        }

        public ByteArrayWriter PutIntMap(SortedDictionary<short, int> extra)
        {
            Put((short) extra.Count);

            foreach (var pair in extra)
            {
                Put(pair.Key);
                Put(pair.Value);
            }

            return this;
        }
    }

    public enum Privilege
    {
        [System.ComponentModel.Description("PrivilegePublishStream")]
        PrivilegePublishStream = 0,

        [System.ComponentModel.Description("PrivilegePublishAudioStream")]
        PrivilegePublishAudioStream = 1,

        [System.ComponentModel.Description("PrivilegePublishVideoStream")]
        PrivilegePublishVideoStream = 2,

        [System.ComponentModel.Description("PrivilegePublishDataStream")]
        PrivilegePublishDataStream = 3,

        [System.ComponentModel.Description("PrivilegeSubscribeStream")]
        PrivilegeSubscribeStream = 4
    }

    public class AccessToken
    {
        public string appID;
        public string appKey;
        public string roomID;
        public string userID;
        public int issuedAt;
        public int expireAt;
        public int nonce;
        public SortedDictionary<short, int> privileges;

        public byte[] signature;
        private Random r = new Random();

        const int VersionLength = 3;
        const int AppIdLength = 24;
        const string Version = "001";

        public static byte[] sha256(string keyString, byte[] message)
        {
            return new HMACSHA256(Encoding.Default.GetBytes(keyString)).ComputeHash(message);
        }

        public static int GetTimestamp()
        {
            TimeSpan ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0);
            return Convert.ToInt32(ts.TotalSeconds);
        }

        public static string Generate(string appId, string appKey, string roomId, string userId, int expireAt, SortedDictionary<Privilege, int> previlege)
        {
            var a = new AccessToken(appId, appKey, roomId, userId, expireAt);
            if (previlege != null)
            {
                foreach (var i in previlege)
                {
                    a.AddPrivilege(i.Key, i.Value);
                }
            }

            return a.Serialize();
        }

        public AccessToken()
        {
        }

        public AccessToken(string appID, string appKey, string roomID, string userID, int expireAt)
        {
            this.appID = appID;
            this.appKey = appKey;
            this.roomID = roomID;
            this.userID = userID;
            this.issuedAt = GetTimestamp();
            this.nonce = r.Next();
            this.privileges = new SortedDictionary<short, int>();
            this.expireAt = expireAt;
        }

        public void AddPrivilege(Privilege privilege, int expireTimestamp)
        {
            privileges.Add((short) privilege, expireTimestamp);

            if (privilege == Privilege.PrivilegePublishStream)
            {
                privileges.Add((short) Privilege.PrivilegePublishVideoStream, expireTimestamp);
                privileges.Add((short) Privilege.PrivilegePublishAudioStream, expireTimestamp);
                privileges.Add((short) Privilege.PrivilegePublishDataStream, expireTimestamp);
            }
        }

        private byte[] PackMsg()
        {
            return new ByteArrayWriter()
                .Put(nonce)
                .Put(issuedAt)
                .Put(expireAt)
                .Put(roomID)
                .Put(userID)
                .PutIntMap(privileges)
                .AsBytes();
        }

        // Serialize generates the token string
        public string Serialize()
        {
            byte[] msg = PackMsg();
            signature = sha256(this.appKey, msg);
            byte[] content = new ByteArrayWriter().Put(msg).Put(signature).AsBytes();
            return Version + appID + Convert.ToBase64String(content);
        }

        // Verify checks if this token valid, called by server side.
        public bool Verify(string appKey)
        {
            if (this.expireAt > 0 && GetTimestamp() > this.expireAt)
            {
                return false;
            }

            var signature2 = sha256(appKey, PackMsg());
            return Convert.ToBase64String(signature2).Equals(Convert.ToBase64String(signature));
        }

        // Parse retrieves token information from raw string
        public static AccessToken Parse(string raw)
        {
            AccessToken token = new AccessToken();
            if (raw.Length <= VersionLength + AppIdLength)
            {
                throw new ArgumentException("invalid string");
            }

            if (!Version.Equals(raw.Substring(0, VersionLength)))
            {
                throw new ArgumentException("invalid VERSION");
            }

            token.appID = raw.Substring(VersionLength, AppIdLength);
            byte[] content = Convert.FromBase64String(raw.Substring(VersionLength + AppIdLength, raw.Length - VersionLength - AppIdLength));
            var buffer = new ByteArrayReader(content);
            byte[] msg = buffer.ReadBytes();
            token.signature = buffer.ReadBytes();
            var msgBuf = new ByteArrayReader(msg);
            token.nonce = msgBuf.ReadInt();
            token.issuedAt = msgBuf.ReadInt();
            token.expireAt = msgBuf.ReadInt();
            token.roomID = msgBuf.ReadString();
            token.userID = msgBuf.ReadString();
            token.privileges = msgBuf.ReadIntMap();
            return token;
        }

        public override string ToString()
        {
            StringBuilder cout = new StringBuilder();
            cout.Append($@"nonce={nonce}
roomId={roomID}
appId={appID}
userId={userID}
issuedAt={issuedAt}
expireAt={expireAt}
");
            foreach (var i in privileges)
            {
                cout.Append($"Privilege:{(Privilege) i.Key}=>{i.Value}\n");
            }

            return cout.ToString();
        }
    }
}