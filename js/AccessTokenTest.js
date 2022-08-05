// docker run -it --rm -v "$PWD/nodejs/src":/usr/src -w /usr/src node node AccessTokenTest.js

var AccessToken = require('./AccessToken');

var Privileges = require('./AccessToken').privileges;


var appID = "123456781234567812345678";
var appKey = "app key";
var roomID = "new room";
var userID = "new user id";


var key = new AccessToken.AccessToken(appID, appKey, roomID, userID);

key.addPrivilege(Privileges.PrivSubscribeStream, 0);
key.addPrivilege(Privileges.PrivPublishStream, Math.floor(new Date() / 1000) + (24 * 3600));
key.expireTime(Math.floor(new Date() / 1000) + (24 * 3600));

var s = key.serialize();

console.log(s);

var key2 = AccessToken.Parse(s);

console.log(key2);

console.log(key2.verify(appKey));


