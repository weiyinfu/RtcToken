using System;
using System.Collections.Generic;

namespace RtcToken
{
    internal class Program
    {
        public static void demo1()
        {
            var appId = "xxx";
            var appKey = "xxx";
            var a = new AccessToken(appId, appKey, "1", "1", AccessToken.GetTimestamp() + 3600);
            a.AddPrivilege(Privilege.PrivilegePublishStream, AccessToken.GetTimestamp() + 3600);
            var token = a.Serialize();
            Console.WriteLine($"serialize result={token}");
            Console.WriteLine(a);
            var b = AccessToken.Parse(token);
            Console.WriteLine($"parsed result={b}");
            var verifyResult = b.Verify(appKey);
            Console.WriteLine($"verifyResult={verifyResult}");
        }

        public static void Main(string[] args)
        {
            var appId = "619cdddd9e93d300c49e5ad4";
            var appKey = "bbe031af107844fc957ffbc6748116c9";
            var privilege = new SortedDictionary<Privilege, int>();
            privilege.Add(Privilege.PrivilegePublishStream, AccessToken.GetTimestamp() + 3600 * 8);
            privilege.Add(Privilege.PrivilegeSubscribeStream, AccessToken.GetTimestamp() + 3600 * 8);
            Console.WriteLine(AccessToken.Generate(appId, appKey, "1", "1", AccessToken.GetTimestamp() + 3600 * 8, privilege));
        }
    }
}