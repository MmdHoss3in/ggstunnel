package carrier

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"ggstunnel/internal/config"
	"ggstunnel/internal/frame"
)

func compactPair(t *testing.T)(*BIP,*BIP){
	t.Helper()
	newPeer:=func(role string)*BIP{c:=simConfig(role);c.Transport.BIPWireMode="compact";x,err:=NewBIP(c);if err!=nil{t.Fatal(err)};return x.(*BIP)}
	return newPeer("server"),newPeer("client")
}

func TestCompactWireEveryKindAndAuthenticatedTampering(t *testing.T){
	a,b:=compactPair(t)
	for kind:=byte(1);kind<=10;kind++{
		payload:=[]byte("GGS-PACK1-OFFER")
		if kind==bipKindAck{payload=make([]byte,8)}
		p:=wirePacket{typ:8,kind:kind,sender:a.localID,target:b.localID,number:uint64(kind),id:17,tuple:29,ack:1,sack:5,token:7,payload:payload}
		if kind!=bipKindFastProbe && kind!=bipKindFastAck && kind!=bipKindData {p.token=0}
		if kind>=bipKindHello{p.ack=0;p.sack=0}
		wire,err:=a.encode(p);if err!=nil{t.Fatal(err)}
		if bytes.Contains(wire,[]byte(bipMagic)) || bytes.Contains(wire,payload){t.Fatal("clear-text marker exposed")}
		got,err:=b.decode(wire);if err!=nil{t.Fatalf("kind %d: %v",kind,err)}
		if got.sender!=p.sender || got.target!=p.target || got.number!=p.number || got.ack!=p.ack || got.sack!=p.sack || got.token!=p.token || !bytes.Equal(got.payload,payload){t.Fatalf("roundtrip differs kind %d",kind)}
		for _,pos:=range []int{0,1,4,6,8,16,20,len(wire)-1}{
			bad:=append([]byte(nil),wire...);bad[pos]^=1;binary.BigEndian.PutUint16(bad[2:4],0);binary.BigEndian.PutUint16(bad[2:4],checksum(bad))
			if _,err:=b.decode(bad);err==nil{t.Fatalf("tampered byte %d accepted",pos)}
		}
	}
	wrong:=simConfig("client");wrong.Transport.BIPWireMode="compact";wrong.PSK="different0123456789abcdef01234567";x,_:=NewBIP(wrong)
	wire,_:=a.encode(wirePacket{typ:8,kind:bipKindHello,sender:a.localID,number:100,payload:[]byte{a.localRole()}})
	if _,err:=x.(*BIP).decode(wire);err==nil{t.Fatal("wrong PSK accepted")}
}

func TestCompactReflectionAndKeyLifetime(t *testing.T){
	a,_:=compactPair(t)
	wire,err:=a.encode(wirePacket{typ:8,kind:bipKindHello,sender:a.localID,number:1,payload:[]byte{a.localRole()}});if err!=nil{t.Fatal(err)}
	wire[0]=0;binary.BigEndian.PutUint16(wire[2:4],0);binary.BigEndian.PutUint16(wire[2:4],checksum(wire))
	a.handle(wire,time.Now())
	if a.reflectionsSuppressed.Load()!=1 || a.active!=0 || !a.lastPeerActivity.IsZero(){t.Fatal("kernel reflection authenticated a peer")}
	a.emit=func([]byte)error{return nil};a.packetNo=0xffffffff
	if _,err:=a.prepareWire(8,1,1,bipKindHello,0,0,nil,0);!errors.Is(err,frame.ErrKeyLifetime){t.Fatal("counter reused")}
}

func TestCompactPeerReplyDoesNotDeriveAnOwnReflectionKey(t *testing.T){
	a,b:=compactPair(t)
	wire,err:=a.encode(wirePacket{typ:0,kind:bipKindHello,sender:a.localID,number:1,payload:[]byte{a.localRole()}});if err!=nil{t.Fatal(err)}
	if b.compactReflection(wire){t.Fatal("peer reply treated as own echo")}
	if b.compactSend!=nil || b.compactReceive!=nil{t.Fatal("reflection prefilter touched peer key state")}
	if _,err:=b.decode(wire);err!=nil{t.Fatal(err)}
}

func TestCompactEncryptedFramePackingAndReplay(t *testing.T){
	a,b:=compactPair(t);sender,_:=frame.NewCodec(a.cfg.PSK);receiver,_:=frame.NewCodec(a.cfg.PSK)
	if err:=a.BindIdentity(sender.SessionID());err!=nil{t.Fatal(err)}
	var packed []byte; packed=append(packed,2)
	for i:=0;i<2;i++{sealed,err:=sender.Seal(frame.TypeData,uint32(i),0,1,bytes.Repeat([]byte{byte(i)},200));if err!=nil{t.Fatal(err)};packed=appendPackedFrame(packed,sealed)}
	wire,err:=a.encode(wirePacket{typ:8,kind:bipKindData,flags:bipFlagPacked,sender:a.localID,target:b.localID,number:1,token:1,payload:packed});if err!=nil{t.Fatal(err)}
	got,err:=b.decode(wire);if err!=nil || !bytes.Equal(got.payload,packed){t.Fatalf("packed ciphertext changed %v",err)}
	pos:=1
	for i:=0;i<2;i++{n:=int(binary.BigEndian.Uint16(got.payload[pos:]));pos+=2;sealed:=got.payload[pos:pos+n];pos+=n
		if _,err:=receiver.OpenForSession(sealed,a.localID);err!=nil{t.Fatal(err)}
		if _,err:=receiver.OpenForSession(sealed,a.localID);!errors.Is(err,frame.ErrReplay){t.Fatal("inner replay accepted")}
	}
}

func TestCompactSimulatedLossReorderAndStrictStateful(t *testing.T){
	for _,stateful:=range []bool{false,true}{t.Run(map[bool]string{false:"loss-reorder",true:"single-reply-stateful"}[stateful],func(t *testing.T){
		ctx,cancel:=context.WithCancel(context.Background());defer cancel()
		l:=&simLink{adaptive:true,copies:1,stateful:stateful,singleReply:stateful,dropFirst:true,reorder:!stateful,requests:make(map[[3]uint16]time.Time)}
		l.configure=func(c *config.Config){c.Transport.BIPWireMode="compact"}
		a:=l.start(t,0,ctx);b:=l.start(t,1,ctx)
		waitFor(t,func()bool{return a.PeerSession()==b.localID && b.PeerSession()==a.localID})
		for _,peers:=range [][2]*BIP{{a,b},{b,a}}{
			for i:=0;i<32;i++{if err:=peers[0].Send([]byte{byte(i),42});err!=nil{t.Fatal(err)}}
			for i:=0;i<32;i++{select{case p:=<-peers[1].Recv():if !bytes.Equal(p,[]byte{byte(i),42}){t.Fatal("ordered payload changed")};case <-time.After(3*time.Second):t.Fatal("compact transfer stalled")}}
		}
	})}
}

func FuzzCompactWireParser(f *testing.F){
	f.Add([]byte{0});f.Add(make([]byte,compactMinimum))
	c:=simConfig("server");c.Transport.BIPWireMode="compact";x,err:=NewBIP(c);if err!=nil{f.Fatal(err)};a:=x.(*BIP)
	seed,err:=a.encode(wirePacket{typ:8,kind:bipKindHello,sender:a.localID,number:1,payload:[]byte{a.localRole()}});if err!=nil{f.Fatal(err)};f.Add(seed)
	f.Fuzz(func(t *testing.T,body []byte){a,b:=compactPair(t);_ = a;b.decode(body);b.compactReflection(body)})
}

func TestCompactTuplePermutationIsUniqueAndSessionSpecific(t *testing.T){
	a,b:=compactPair(t);_ = b
	seen:=make(map[uint32]bool)
	for i:=0;i<65536;i++ {id,seq:=a.nextTuple();tuple:=uint32(id)<<16|uint32(seq);if seen[tuple]{t.Fatal("request tuple collision")};seen[tuple]=true}
	before:=permuteCompactTuple(a.compactSend.tuple,17)
	if err:=a.BindIdentity(a.localID+1);err!=nil{t.Fatal(err)}
	a.nextTuple()
	if before==permuteCompactTuple(a.compactSend.tuple,17){t.Fatal("new session retained tuple mapping")}
}

func TestCompactShortOutageAndPeerRestart(t *testing.T){
	ctx,cancel:=context.WithCancel(context.Background());defer cancel()
	l:=&simLink{adaptive:true,copies:2,requests:make(map[[3]uint16]time.Time)}
	l.configure=func(c *config.Config){c.Transport.BIPWireMode="compact"}
	a:=l.start(t,0,ctx);b:=l.start(t,1,ctx)
	waitFor(t,func()bool{return a.PeerSession()==b.localID && b.PeerSession()==a.localID})
	blocked:=true;l.mu.Lock();l.filter=func(int,[]byte)bool{return !blocked};l.mu.Unlock()
	if err:=a.Send([]byte("retained during outage"));err!=nil{t.Fatal(err)}
	time.Sleep(300*time.Millisecond)
	l.mu.Lock();blocked=false;l.mu.Unlock()
	select{case got:=<-b.Recv():if string(got)!="retained during outage"{t.Fatal("payload changed")};case <-time.After(3*time.Second):t.Fatal("outage did not resume")}
	waitFor(t,func()bool{return a.SnapshotStats().Pending==0})
	b.Close();fresh:=l.start(t,1,ctx)
	waitFor(t,func()bool{return a.PeerSession()==fresh.localID && fresh.PeerSession()==a.localID})
	if err:=fresh.Send([]byte("new authenticated peer"));err!=nil{t.Fatal(err)}
	select{case got:=<-a.Recv():if string(got)!="new authenticated peer"{t.Fatal("restart payload changed")};case <-time.After(3*time.Second):t.Fatal("peer restart did not resume")}
}

func TestCompactDoesNotDowngradeToLegacyPeer(t *testing.T){
	ctx,cancel:=context.WithCancel(context.Background());defer cancel()
	l:=&simLink{copies:1,requests:make(map[[3]uint16]time.Time)}
	l.configure=func(c *config.Config){c.Transport.BIPHandshakeTimeoutSec=1;if c.Role=="server"{c.Transport.BIPWireMode="compact"}}
	a:=l.start(t,0,ctx);l.start(t,1,ctx)
	select{case err:=<-a.Errors():if !errors.Is(err,ErrBIPHandshakeTimeout){t.Fatal(err)};case <-time.After(3*time.Second):t.Fatal("mixed wire modes hung forever")}
	if a.PeerSession()!=0 || !a.compactMode(){t.Fatal("unauthenticated downgrade occurred")}
}

func FuzzCompactAuthenticatedBounds(f *testing.F){
	f.Add([]byte{7,0,0,0,0,0,0,0,12,1,0})
	f.Add([]byte{5,0,0,0,0,0,0,0,12,0})
	f.Fuzz(func(t *testing.T,plain []byte){
		if len(plain)>1444 {return}
		a,b:=compactPair(t)
		if err:=a.BindIdentity(11);err!=nil{t.Fatal(err)}
		if err:=b.BindIdentity(12);err!=nil{t.Fatal(err)}
		keys,err:=a.compactKeysFor(a.localID,a.localRole());if err!=nil{t.Fatal(err)}
		// An isolated public test key deliberately admits arbitrary authenticated
		// plaintext so fuzzing reaches the semantic parser after AEAD verification.
		nonce:=compactNonce(keys.alias,1)
		body:=make([]byte,compactPrefix,compactPrefix+len(plain)+16);body[0]=8;copy(body[8:20],nonce[:]);aad:=compactAAD(body,8,nonce)
		body=keys.aead.Seal(body,nonce[:],plain,aad[:])
		if len(body)<compactPrefix+16{return}
		var mask [16]byte;keys.header.Encrypt(mask[:],body[compactPrefix:compactPrefix+16]);for i:=0;i<4;i++{body[16+i]^=mask[i]}
		binary.BigEndian.PutUint16(body[2:4],checksum(body))
		got,err:=b.decode(body)
		if err==nil && got.kind==bipKindData && len(got.payload)>b.cfg.Performance.MaxFramePayload+60{t.Fatal("expanded payload exceeded configured bound")}
	})
}
