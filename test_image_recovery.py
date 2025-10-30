#!/usr/bin/env python3
"""
통합 로그에서 이미지 파일 복구 테스트 스크립트
unified_requests.json에서 attachment 정보를 읽어 실제 이미지 파일로 저장
"""
import json
import base64
from pathlib import Path
from datetime import datetime

def recover_images():
    
    file_data="RIFF2\b\u0000\u0000WEBPVP8 &\b\u0000\u0000 K\u0000 \u0001* \u0002\u000e\u0001>m6 I #\"   \u0018\u0010 \r in v \u0001\u0013\n ~   n  } 3б G c \u0003      LC\u0014 \u001dh# _  o ۝ \u001d k \u0005 / z]?a \u0000 ;  ϋ 9 ] \t 0   \u000b \u0000\u0010| ӧN :t ӧN :t Ӧ \u000fm      P \ne<7 \u0014u\u0017 \u0005D ! =5 z\u0010垚  \br Mvބ9g  oB\u001c  ]   \u0000 7 {\u0016p\u000eoX z~ d  \u001b\u0017\u0000< Ç\u000e\u001c8p Ç\u000e\u001c8l  `  5  H\u0003Ү ^>}ʄ \\  P5 \u000f  t    k\u0002   6\u0007 }\u0012SE~\u0007   = :t ӧN :t Ӥ i    \u0014\u00038 `'4  b>\u0000  V  \u0002\u0012 h  hɫ    *C  l {  /A \nb  T\u0006 \u0018łTV   x r n\b9  8p Ç\u000e\u001c8p \u000b  \u0004  X   \n     )O\b\u0019V\u000ei \u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p Ç\u000e\u001c8p \u0000\u0000  ƛ\u000b   m \u0000 \u001f    Z <Ir\u000b  dl \u001d  \u001e\u001a O   %+ Cp \u000f  p  ?1 W  FS I  R  j j     /d u( њ]U $7Z  c9;Z   pY \u0011y \u000be\u000fq  j  [7   1? æH- ;  &\u0016   IBZS\u000fJS \u000b\u0013 %    2 aׇOv  = {  i  ݧ Ov  = {  kasS    \u0004 칶 ? .m O ˛l\u0013    \u0004 칶 ? .m O ˛l\u0013    \u0004 칶 ? .m O ˛l\u000e  S# %y \u001b=cﾕ\f\u0011 '<\u001aߘ ,H +' J \u001d\u001f;p\u0003DP  \u0002* U@\u0000\u0000\u0000L\u0005\"  os< NT,~  KY5    ǎ\b 7OM     x\u0011 s6\u001b\u0002\u001bo !ƞ\u0012   w \u0010 x  ֪  H\u000bI\u001dB(D  %\u0001\u001b  # &   : b\u0005ժ   T?St |蜩  \u0019 8>\"  Hx\u0005 珮 o\u0000 \u0004\u001e'\u0006 \u0001 \t\u001fV \u001f \u001b   &   \u0004\u0017t  9 0\n  I   '$U-Z6@  :x 8B   \u000f~ \u001a H N  ˿  |B a    ! o qƻM -     \\e   b\u0007  \u001e  T(   %y/ t  b  D  2  ng 1 {  N\u001fd> \u0015   {   *\u0017L \u0013 \u0013\\\u0004 :    ?.J\\Y : d  $ \u001c Ձ\u0017Jy \u001e\u0001 Dl H \\o1 5 \u0006ƺ\"\u000b\u0005  *\u0017   \u0010_bO  i 4\u000b 5 .)f\u001b  & \u001f _  N \u0003,2F T  G ( \u001c  \u001c ?\u0018\u0003 Ƥo^:&c  E   E t \u0001)\b \u0001 \u001b\u0001   Vt vIS ) y\f\u0002My^ =  b\u0005\t m \u000f   v   # `p   x Ӱ\u001c \u0000X \u0001  H0 a5 b   b\u0014D\u0002˗hp\u0001  %= \u001a]A܉   J jy Lt\bY    s\u001e     \u001b\u000e.  \u001c = :  \u0012D\u0012 \u000e I\u0012  }˧   \u0018 j< \u001e  լ  | \u0001\u001b    lɉ  7 B\u000ei(  (  O\f  $w N  Sg\u0012Փ  \"  < \u0019 .  L Φ\n[\u0002 C޿  2\u0014\u0017\u0012UX 0h \u0014   S    \u0000 \u001b U `ܡ ɾ  p \u001a \u0014m  p    (  J / @ ϸ@ 1\"<> od U       n  \u001ae Qm\"   E~I%  G Ɵ %p  \u001d  m}~9)\u0018 i D   |j\fwX     G\u001dq3   1 o\f̕˥ua  ʹ   \u0005 G } [ ;f> l  Vv5o G l 2\f \u0017\u0010  g iI]Yp2B Iev  Q t\u0014 A #V  h Y\u001e7(>  -  \u0014  9 Ii$   \u0010 \u0005\u0001\u001c ()> ֔  o \u0001\u001b\\ \u000e\u0001 <p  (\u0006 ? :6\by\tzv \u0014d 9y +R  $ xt     Fw 4V\u0016 G   * \u0002 @  ͚  t *  E{\u000f ɿq@c  DcBiF  \r e'LYys.SO \u0019\u001b     G&L\u0002X \\   CUX\u001b\u001f 7\u0018\\  n    \u0001o '$  b FIp \u000e \u0013`G\u0011D\u000fT Ao \u0017\u0001[  e < Sr   F([ A /;\u0002 \u001f{\u000f /  \u001c q  i'  \u001f\"  <   Z    I\u001e 5 Ds`\u0000\u0000\tv  \u0006Cj~ M#\u0017 Jm \t\u0017\u0013\u0000\u0010X\n \b\\3L\u000e\u0011  \u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000"

    # 파일명 생성 (시간 + 인덱스)
    filename = f"image_{datetime.now().strftime('%Y%m%d_%H%M%S')}.webp"
    output_path = Path(f"./images/{filename}")  # 문자열이 아닌 Path 객체로 만듦
    output_path.parent.mkdir(parents=True, exist_ok=True)  # 폴더 없으면 생성


    # Base64 → 바이너리 디코딩
    binary_data = base64.b64decode(file_data)

    # 이미지 파일 저장
    output_path.write_bytes(binary_data)





if __name__ == "__main__":
    recover_images()
