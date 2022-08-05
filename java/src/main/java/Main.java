import io.rtc.AccessToken;
import io.rtc.Utils;

public class Main {
    public static void main(String[] args) {
        String appId = "xxxx";
        String appKey = "xxxx";
        AccessToken a = new AccessToken(appId, appKey, "1", "1");
        a.ExpireTime(Utils.getTimestamp() + 3600 * 3);
        a.AddPrivilege(AccessToken.Privileges.PrivPublishStream, Utils.getTimestamp() + 3600 * 3);
        String res = a.Serialize();
        System.out.printf("signature=%s \nserialize result=%s a=%s", a.signature, res, a);
    }
}
