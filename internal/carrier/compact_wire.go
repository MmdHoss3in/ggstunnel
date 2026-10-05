package carrier

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"

	"ggstunnel/internal/config"
	"ggstunnel/internal/frame"
)

// This is a private PSK carrier format, not QUIC or TLS. AES-based ciphertext
// sampling protects the packet counter (RFC 9001 section 5.4.3's primitive).
// Separate HKDF domains isolate role aliases, AEAD keys and header keys.
const compactPrefix = 20 // ICMP8, per-session opaque alias8, masked counter4
const compactMinimum = compactPrefix+16+10 // kind/flags, target, padding count

type compactKeys struct {
	id uint64
	role byte
	alias uint64
	aead cipher.AEAD
	header cipher.Block
	tuple cipher.Block
}

func wireVersion(c *config.Config) uint16 {
	if c.Transport.BIPWireMode == "compact" { return 6 }
	return 5
}

func (b *BIP) compactMode() bool { return b.cfg.Transport.BIPWireMode == "compact" }

func (b *BIP) aliasMask(role byte) (uint64,error) {
	if role<1 || role>2 {return 0,errBIPBadMAC}
	if b.compactAliasReady[role] {return b.compactAliasMasks[role],nil}
	key,err := hkdf.Key(sha256.New,b.master,nil,fmt.Sprintf("ggstunnel/compact/alias/v1/%d",role),8)
	if err != nil {return 0,err}
	b.compactAliasMasks[role]=binary.BigEndian.Uint64(key)
	b.compactAliasReady[role]=true
	return b.compactAliasMasks[role],nil
}

func (b *BIP) compactKeysFor(id uint64, role byte) (*compactKeys,error) {
	if id == 0 { return nil,errBIPBadMAC }
	var salt [8]byte; binary.BigEndian.PutUint64(salt[:],id)
	derive := func(domain string)([]byte,error){return hkdf.Key(sha256.New,b.master,salt[:],fmt.Sprintf("ggstunnel/compact/%s/v1/%d",domain,role),32)}
	key,err:=derive("aead"); if err!=nil{return nil,err}
	block,err:=aes.NewCipher(key);if err!=nil{return nil,err}
	aead,err:=cipher.NewGCM(block);if err!=nil{return nil,err}
	hp,err:=derive("header");if err!=nil{return nil,err}
	header,err:=aes.NewCipher(hp);if err!=nil{return nil,err}
	tupleKey,err:=derive("tuple");if err!=nil{return nil,err}
	tuple,err:=aes.NewCipher(tupleKey);if err!=nil{return nil,err}
	mask,err:=b.aliasMask(role);if err!=nil{return nil,err}
	return &compactKeys{id:id,role:role,alias:id^mask,aead:aead,header:header,tuple:tuple},nil
}

// Four-round keyed Feistel permutation: unique request tuples without a
// visibly increasing sequence. Replies still copy the request tuple exactly.
// This is not a substitute for authentication or for header encryption.
func permuteCompactTuple(block cipher.Block, counter uint32)uint32{
	left,right:=uint16(counter>>16),uint16(counter)
	var in,out [16]byte
	for round:=byte(0);round<4;round++ {
		in[0]=round;binary.BigEndian.PutUint16(in[1:3],right)
		block.Encrypt(out[:],in[:])
		left,right=right,left^binary.BigEndian.Uint16(out[:2])
	}
	return uint32(left)<<16|uint32(right)
}

func (b *BIP) nextCompactTuple()(uint16,uint16){
	k:=b.compactSend
	if k==nil || k.id!=b.localID {
		var err error;k,err=b.compactKeysFor(b.localID,b.localRole());if err!=nil{b.fail(err);return 0,0};b.compactSend=k
	}
	b.compactTupleNo++
	if b.compactTupleNo>0xffffffff{b.fail(frame.ErrKeyLifetime);return 0,0}
	tuple:=permuteCompactTuple(k.tuple,uint32(b.compactTupleNo))
	return uint16(tuple>>16),uint16(tuple)
}

func compactNonce(alias uint64, number uint32) [12]byte {
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[:8],alias)
	binary.BigEndian.PutUint32(nonce[8:],number)
	return nonce
}

func compactAAD(body []byte, typ byte, nonce [12]byte) [18]byte {
	var aad [18]byte
	aad[0],aad[1]=typ,body[1]
	copy(aad[2:6],body[4:8])
	copy(aad[6:],nonce[:])
	return aad
}

func (b *BIP) encodeCompact(p wirePacket)([]byte,error){
	if p.number==0 || p.number>0xffffffff || p.sender!=b.localID {return nil,frame.ErrKeyLifetime}
	k:=b.compactSend
	if k==nil || k.id!=p.sender {
		var err error;k,err=b.compactKeysFor(p.sender,b.localRole());if err!=nil{return nil,err};b.compactSend=k
	}
	payload:=p.payload
	if p.kind==bipKindData {
		var err error;payload,err=compactPayload(payload,p.sender,p.flags&bipFlagPacked!=0,false,b.cfg.Performance.MaxFramePayload+60);if err!=nil{return nil,err}
	}
	plain:=make([]byte,1,32+len(payload))
	plain[0]=p.kind | p.flags<<4
	plain=binary.BigEndian.AppendUint64(plain,p.target)
	if p.kind<bipKindHello {
		plain=binary.BigEndian.AppendUint32(plain,p.ack)
		if p.sack!=0 {plain[0]|=0x80;plain=binary.BigEndian.AppendUint64(plain,p.sack)}
		if p.kind==bipKindFastProbe || p.kind==bipKindFastAck || p.kind==bipKindData {plain=binary.BigEndian.AppendUint32(plain,p.token)}
	}
	plain=append(plain,payload...)
	padding:=byte(0)
	if p.kind!=bipKindData {
		var random [16]byte;if _,err:=rand.Read(random[:]);err!=nil{return nil,err}
		padding=random[0]&15;plain=append(plain,random[1:1+int(padding)]...)
	}
	plain=append(plain,padding)
	if compactPrefix+len(plain)+16>1480 {return nil,syscall.EMSGSIZE}
	body:=make([]byte,compactPrefix,compactPrefix+len(plain)+16)
	body[0]=p.typ;binary.BigEndian.PutUint16(body[4:6],p.id);binary.BigEndian.PutUint16(body[6:8],p.tuple)
	nonce:=compactNonce(k.alias,uint32(p.number));copy(body[8:20],nonce[:]);aad:=compactAAD(body,p.typ,nonce)
	body=k.aead.Seal(body,nonce[:],plain,aad[:])
	var mask [16]byte;k.header.Encrypt(mask[:],body[compactPrefix:compactPrefix+16])
	for i:=0;i<4;i++ {body[16+i]^=mask[i]}
	binary.BigEndian.PutUint16(body[2:4],checksum(body))
	return body,nil
}

// openCompact never commits replay/liveness/session state. Cache a candidate
// sender key only after AEAD verification; memory remains bounded to two keys.
func (b *BIP) openCompact(body []byte, role, typ byte)(wirePacket,error){
	var p wirePacket
	if len(body)<compactMinimum || len(body)>1480 || body[1]!=0 || (body[0]!=0 && body[0]!=8) || checksum(body)!=0 {return p,errors.New("malformed compact packet")}
	alias:=binary.BigEndian.Uint64(body[8:16]);mask,err:=b.aliasMask(role);if err!=nil{return p,err}
	id:=alias^mask
	k:=b.compactReceive
	if role==b.localRole(){k=b.compactSend}
	if k==nil || k.id!=id || k.role!=role {k,err=b.compactKeysFor(id,role);if err!=nil{return p,err}}
	var hp [16]byte;k.header.Encrypt(hp[:],body[compactPrefix:compactPrefix+16])
	var counter [4]byte;for i:=0;i<4;i++{counter[i]=body[16+i]^hp[i]}
	number:=binary.BigEndian.Uint32(counter[:]);if number==0{return p,errBIPBadMAC}
	nonce:=compactNonce(alias,number);aad:=compactAAD(body,typ,nonce)
	plain,err:=k.aead.Open(nil,nonce[:],body[compactPrefix:],aad[:]);if err!=nil{return p,errBIPBadMAC}
	if role==b.remoteRole(){b.compactReceive=k}
	if len(plain)<10 {return p,errors.New("short compact plaintext")}
	padding:=int(plain[len(plain)-1]);if padding>15 || padding>len(plain)-10{return p,errors.New("invalid compact padding")}
	plain=plain[:len(plain)-1-padding]
	p=wirePacket{typ:body[0],kind:plain[0]&15,flags:(plain[0]>>4)&7,id:binary.BigEndian.Uint16(body[4:6]),tuple:binary.BigEndian.Uint16(body[6:8]),sender:id,number:uint64(number),target:binary.BigEndian.Uint64(plain[1:9])}
	if p.kind<1 || p.kind>10 || (p.flags&(bipFlagPulled|bipFlagPacked)!=0 && p.kind!=bipKindData) {return p,errors.New("invalid compact kind/flags")}
	pos:=9
	if p.kind<bipKindHello {
		if pos+4>len(plain){return p,errors.New("short compact ACK")};p.ack=binary.BigEndian.Uint32(plain[pos:]);pos+=4
		if plain[0]&0x80!=0 {if pos+8>len(plain){return p,errors.New("short compact SACK")};p.sack=binary.BigEndian.Uint64(plain[pos:]);pos+=8}
		if p.kind==bipKindFastProbe || p.kind==bipKindFastAck || p.kind==bipKindData {if pos+4>len(plain){return p,errors.New("short compact token")};p.token=binary.BigEndian.Uint32(plain[pos:]);pos+=4}
	}else if plain[0]&0x80!=0 {return p,errors.New("unexpected bootstrap SACK")}
	p.payload=plain[pos:]
	if p.kind==bipKindData {
		if padding!=0{return p,errors.New("padded compact DATA")}
		p.payload,err=compactPayload(p.payload,p.sender,p.flags&bipFlagPacked!=0,true,b.cfg.Performance.MaxFramePayload+60);if err!=nil{return p,err}
	}
	if p.kind==bipKindAck && (len(p.payload)>(b.ackSpan()/64-1)*8 || len(p.payload)%8!=0){return p,errors.New("invalid compact ACK extension")}
	return p,nil
}

func (b *BIP) decodeCompact(body []byte)(wirePacket,error){
	p,err:=b.openCompact(body,b.remoteRole(),bodyType(body));if err==nil {b.wireRxBytes.Add(uint64(len(body)+20))};return p,err
}

func bodyType(body []byte)byte {if len(body)>0{return body[0]};return 0}

func (b *BIP) compactReflection(body []byte) bool {
	if len(body)<compactMinimum || body[0]!=0{return false}
	mask,err:=b.aliasMask(b.localRole())
	if err!=nil || binary.BigEndian.Uint64(body[8:16])!=b.localID^mask {return false}
	p,err:=b.openCompact(body,b.localRole(),8)
	return err==nil && p.sender==b.localID
}

func compactPayload(payload []byte, sender uint64, packed, expand bool, limit int)([]byte,error){
	convert:=func(p []byte)([]byte,error){
		if expand {out,err:=frame.ExpandCompact(p,sender);if err!=nil{return nil,err};if len(out)>limit{return nil,frame.ErrMalformed};return out,nil}
		if len(p)>limit{return nil,frame.ErrMalformed};return frame.Compact(p,sender),nil
	}
	if !packed{return convert(payload)}
	if len(payload)<1 || payload[0]<2 || payload[0]>16 {return nil,frame.ErrMalformed}
	out:=[]byte{payload[0]};pos:=1
	for i:=0;i<int(payload[0]);i++{
		if pos+2>len(payload){return nil,frame.ErrMalformed};size:=int(binary.BigEndian.Uint16(payload[pos:]));pos+=2
		if size==0 || size>len(payload)-pos{return nil,frame.ErrMalformed}
		part,err:=convert(payload[pos:pos+size]);if err!=nil{return nil,err};pos+=size
		out=appendPackedFrame(out,part)
		if len(out)>min(1480,limit+16){return nil,frame.ErrMalformed}
	}
	if pos!=len(payload){return nil,frame.ErrMalformed}
	if expand {if _,ok:=validatePacked(out,limit);!ok{return nil,frame.ErrMalformed}}
	return out,nil
}

func (b *BIP) acceptsWireBody(body []byte)bool{
	if b.compactMode(){return len(body)>=compactMinimum && len(body)<=1480 && (body[0]==0 || body[0]==8) && body[1]==0}
	return len(body)>=72 && len(body)<=1480 && string(body[8:12])==bipMagic
}
