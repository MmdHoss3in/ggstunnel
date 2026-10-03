package frame

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// Retain the previous implementation only as a benchmark/compatibility
// reference. It is not an alternate production encryption path.
func referenceSeal(c *Codec, payload []byte) []byte {
	h := Header{Type: TypeData, SessionID: c.sessionID, Seq:c.seq.Add(1),PacketID:1,FragCount:1}
	header:=marshalHeader(h)
	nonce:=make([]byte,c.aead.NonceSize())
	if _,err:=rand.Read(nonce);err!=nil {panic(err)}
	ciphertext:=c.aead.Seal(nil,nonce,payload,header)
	out:=make([]byte,0,len(header)+len(nonce)+len(ciphertext))
	out=append(out,header...);out=append(out,nonce...);out=append(out,ciphertext...)
	return out
}

func TestSealedBuffersRetainWireCompatibilityAndOwnership(t *testing.T) {
	a,_:=NewCodec("0123456789abcdef")
	b,_:=NewCodec("0123456789abcdef")
	for _,size:=range []int{0,64,1280,65535} {
		input:=bytes.Repeat([]byte{42},size)
		before:=append([]byte(nil),input...)
		sealed,err:=a.Seal(TypeData,1,0,1,input);if err!=nil {t.Fatal(err)}
		if !bytes.Equal(input,before) {t.Fatal("input was modified")}
		retained:=append([]byte(nil),sealed...)
		for i:=range input {input[i]=1}
		other,err:=a.Seal(TypeData,2,0,1,[]byte("next frame"));if err!=nil {t.Fatal(err)}
		other[len(other)-1]^=1
		if !bytes.Equal(retained,sealed) {t.Fatal("retained frame aliased another buffer")}
		decoded,err:=b.Open(sealed);if err!=nil || !bytes.Equal(decoded.Payload,before) {t.Fatal("new wire frame incompatible",err)}
		legacy:=referenceSeal(a,before)
		decoded,err=b.Open(legacy);if err!=nil || !bytes.Equal(decoded.Payload,before) {t.Fatal("previous wire frame incompatible",err)}
	}
}

func BenchmarkCodecSealBuffers(b *testing.B) {
	for _,old:=range []bool{true,false} {
		name:="owned_frame";if old {name="previous_copies"}
		b.Run(name,func(b *testing.B){
			codec,_:=NewCodec("0123456789abcdef")
			payload:=make([]byte,1280)
			b.ReportAllocs();b.SetBytes(int64(len(payload)));b.ResetTimer()
			for i:=0;i<b.N;i++ {
				if old {_=referenceSeal(codec,payload)} else {if _,err:=codec.Seal(TypeData,1,0,1,payload);err!=nil {b.Fatal(err)}}
			}
		})
	}
}
