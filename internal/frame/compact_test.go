package frame

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestCompactPreservesAEADAndBoundary(t *testing.T){
	sender,_:=NewCodec("0123456789abcdef0123456789abcdef")
	receiver,_:=NewCodec("0123456789abcdef0123456789abcdef")
	for _,seq:=range []uint64{1,(1<<32)-1} {
		sender.seq.Store(seq)
		sealed,err:=sender.Seal(TypeData,17,1,2,[]byte("exact ciphertext preserved"));if err!=nil{t.Fatal(err)}
		compact:=Compact(sealed,sender.SessionID())
		if len(compact)!=len(sealed)-19 {t.Fatal("unexpected compact savings")}
		got,err:=ExpandCompact(compact,sender.SessionID());if err!=nil || !bytes.Equal(got,sealed){t.Fatalf("associated data changed: %v",err)}
		if _,err:=receiver.OpenForSession(got,sender.SessionID());err!=nil{t.Fatal(err)}
		wrong,_:=ExpandCompact(compact,sender.SessionID()+1)
		if _,err:=receiver.Open(wrong);err==nil{t.Fatal("wrong sender identity accepted")}
	}
}

func TestCompactRawEscapeAndMalformed(t *testing.T){
	for _,raw:=range [][]byte{nil,[]byte("GGS1 arbitrary"),{1,2,3}} {
		got,err:=ExpandCompact(Compact(raw,9),9);if err!=nil || !bytes.Equal(got,raw){t.Fatal("raw payload changed")}
	}
	bad:=make([]byte,41);bad[0]=TypeData;binary.BigEndian.PutUint16(bad[11:13],129)
	if _,err:=ExpandCompact(bad,9);err==nil{t.Fatal("excess fragment count accepted")}
}

func FuzzCompactFrameBounds(f *testing.F){
	f.Add([]byte{0,42});f.Add([]byte{1})
	f.Fuzz(func(t *testing.T,p []byte){
		got,err:=ExpandCompact(p,9)
		if err==nil && len(p)>0 && p[0]!=0 {
			if _,err:=parseHeader(got);err!=nil{t.Fatal("expanded invalid header")}
			if !bytes.Equal(Compact(got,9),p){t.Fatal("noncanonical compact header")}
		}
	})
}
