package config
import "testing"
func TestBIPHandshakeTimeoutBounds(t *testing.T){
 c:=&Config{Role:"server",Profile:"bip",PSK:"0123456789abcdef0123456789abcdef",Real:RealConfig{LocalIP:"198.51.100.1",PeerIP:"203.0.113.1"},TUN:TUNConfig{LocalAddr:"10.77.1.1",RemoteAddr:"10.77.1.2"}}
 c.ApplyDefaults();if c.Transport.BIPHandshakeTimeoutSec!=90{t.Fatal("wrong bootstrap timeout default")}
 for _,value:=range []int{-1,0,86401}{c.Transport.BIPHandshakeTimeoutSec=value;if c.Validate()==nil{t.Fatalf("invalid deadline accepted %d",value)}}
 c.Transport.BIPHandshakeTimeoutSec=1;if err:=c.Validate();err!=nil{t.Fatal(err)}
}