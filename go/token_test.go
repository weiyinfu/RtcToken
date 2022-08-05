package AccessToken

import (
	"fmt"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	var (
		appID  = "123456781234567812345678"
		appKey = "app key"
		roomID = "new room"
		userID = "new user id"
	)
	token := New(appID, appKey, roomID, userID)
	token.ExpireTime(time.Now().Add(time.Hour * 2))
	token.AddPrivilege(PrivSubscribeStream, time.Time{})
	token.AddPrivilege(PrivPublishStream, time.Now().Add(time.Minute))

	s, err := token.Serialize()
	if err != nil {
		panic(err)
	}
	fmt.Println(s)
	token, err = Parse(s)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%+v\n", token)

	fmt.Println(token.Verify(appKey))
}
