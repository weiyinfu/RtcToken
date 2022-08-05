#include "token/AccessToken.h"
#include <string>

using namespace rtc::tools;

//g++ -Wall -lssl -lcrypto -I/usr/include/openssl/ -L/usr/lib/  ./AccessTokenTest.cpp -o a.out

int main() {
    std::string appID = "123456781234567812345678";
    std::string appKey = "app key";
    std::string roomID = "new room";
    std::string UserID = "new user id";

    AccessToken token(appID, appKey, roomID, UserID);
    token.AddPrivilege(AccessToken::Privileges::PrivSubscribeStream, time(0));
    token.AddPrivilege(AccessToken::Privileges::PrivPublishStream, time(0) + 3600);
    token.ExpireTime(time(0) + 3600 * 2);

    std::string s = token.Serialize();
    printf("token: %s\n", s.c_str());

    AccessToken t = Parse(s);

    printf("appID: %s\n", t.app_id_.c_str());
    printf("appKey: %s\n", t.app_key_.c_str());
    printf("roomID: %s\n", t.room_id_.c_str());
    printf("userID: %s\n", t.user_id_.c_str());
    printf("issuedAt: %d\n", t.issued_at_);
    printf("expireAt: %d\n", t.expire_at_);
    printf("nonce: %d\n", t.nonce_);
    printf("data: %d\n", t.privileges_[AccessToken::Privileges::PrivSubscribeStream]);
    printf("signature: %s\n", t.signature_.c_str());

    printf("verify: %d\n", t.Verify(appKey));

    return 0;
}
