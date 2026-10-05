package carrier

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestUDPQueuedBurstKeepsDatagramBoundaries(t *testing.T){
	peer,err:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4(127,0,0,1)});if err!=nil{t.Fatal(err)};defer peer.Close()
	c:=baseCfg("server","udp");c.ApplyDefaults();c.Performance.QueueSize=512;c.Real.ListenAddr="127.0.0.1:0";c.Real.PeerAddr=peer.LocalAddr().String()
	u:=NewUDP(c);defer u.Close()
	for i:=0;i<100;i++{p:=make([]byte,16+i);binary.BigEndian.PutUint32(p,uint32(i));if err:=u.Send(p);err!=nil{t.Fatal(err)}}
	if err:=u.Start(context.Background());err!=nil{t.Fatal(err)}
	buf:=make([]byte,2048);peer.SetReadDeadline(time.Now().Add(2*time.Second))
	for i:=0;i<100;i++{n,_,err:=peer.ReadFromUDP(buf);if err!=nil{t.Fatal(err)};if n!=16+i || binary.BigEndian.Uint32(buf[:n])!=uint32(i){t.Fatal("datagrams merged, lost or reordered")}}
	for i:=0;i<100;i++{p:=make([]byte,16+i);binary.BigEndian.PutUint32(p,uint32(i));if _,err:=peer.WriteToUDP(p,u.conn.LocalAddr().(*net.UDPAddr));err!=nil{t.Fatal(err)}}
	for i:=0;i<100;i++{select{case p:=<-u.Recv():if len(p)!=16+i || binary.BigEndian.Uint32(p)!=uint32(i){t.Fatal("receive boundaries changed")};case <-time.After(2*time.Second):t.Fatal("batched receive stalled")}}
}
