import sys
import os
import random
import string
import struct
import zlib
import json
import socket
import threading
import time
import base64
import math
import signal

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

HOST = sys.argv[1] if len(sys.argv) > 1 else '144.76.72.157'
PORTA = int(sys.argv[2]) if len(sys.argv) > 2 else 26476
NOME = sys.argv[3] if len(sys.argv) > 3 else 'BOMBC2_'
BOTS = int(sys.argv[4]) if len(sys.argv) > 4 else 3
TEMPO = 0  # MODIFICADO: sempre 0 para conexão infinita
CMD_REGISTRO = sys.argv[5] if len(sys.argv) > 5 else ''  # AJUSTADO: índice mudou
MENSAGENS_RAW = sys.argv[6] if len(sys.argv) > 6 else 'BOMBC2 THE BEST BOTNET 2026'  # AJUSTADO
INTERVALO_MSG = int(sys.argv[7]) if len(sys.argv) > 7 else 6  # AJUSTADO

REGISTRO_USA_PASS = CMD_REGISTRO.startswith('/')

def descrever_registro():
    if not CMD_REGISTRO:
        return '(sem registro)'
    if REGISTRO_USA_PASS:
        return f'{CMD_REGISTRO} <senha_aleatoria>'
    return f'"{CMD_REGISTRO}" (senha fixa)'

MENSAGENS = [m.strip().replace('-', ' ') for m in MENSAGENS_RAW.split('|') if m.strip()]

bots_conectados = 0
bots_ativos = []
tempo_terminado = False  # MODIFICADO: nunca será True
lock_global = threading.Lock()

print(f"( BOMBC2 ) Servidor  : {HOST}:{PORTA}")
print(f"( BOMBC2 ) Bots      : {BOTS}  nome base: \"{NOME}\"")
print(f"( BOMBC2 ) Tempo     : INFINITO (conectado para sempre)")
print(f"( BOMBC2 ) Registro  : {descrever_registro()}")
print(f"( BOMBC2 ) Mensagens : {' | '.join(MENSAGENS)}  cada {INTERVALO_MSG}s")
print()

CARACTERES = string.ascii_lowercase + string.digits

def gerar_nome(base):
    return f"{base}_{''.join(random.choices(CARACTERES, k=6))}"

def senha_aleatoria():
    return ''.join(random.choices(CARACTERES, k=8))

def construir_msg_registro():
    if not CMD_REGISTRO:
        return None
    if REGISTRO_USA_PASS:
        return f"{CMD_REGISTRO} {senha_aleatoria()}"
    return CMD_REGISTRO

def gerar_skin_steve():
    buf = bytearray(64 * 32 * 4)

    def preencher(x0, y0, x1, y1, r, g, b, a=255):
        for y in range(y0, y1):
            for x in range(x0, x1):
                i = (y * 64 + x) * 4
                buf[i] = r; buf[i+1] = g; buf[i+2] = b; buf[i+3] = a

    def px(x, y, r, g, b):
        i = (y * 64 + x) * 4
        buf[i] = r; buf[i+1] = g; buf[i+2] = b; buf[i+3] = 255

    SK = (198, 134, 66)
    HR = (92,  56,  35)
    SH = (67,  95, 175)
    PT = (53,  85, 105)
    BT = (38,  38,  38)

    preencher(8,  0, 16,  8, *HR); preencher(16, 0, 24,  8, *SK)
    preencher( 0, 8,  8, 16, *SK); preencher( 8, 8, 16, 16, *SK)
    preencher(16, 8, 24, 16, *HR); preencher(24, 8, 32, 16, *HR)
    preencher(8, 0, 16, 4, *HR)
    preencher( 9, 9, 11, 11, 255, 255, 255); px(9, 10, 33, 18, 7)
    preencher(13, 9, 15, 11, 255, 255, 255); px(14, 10, 33, 18, 7)
    px(11, 11, *SK); px(12, 11, *SK)
    px(11, 12, 140, 80, 30); px(12, 12, 140, 80, 30)
    preencher(10, 13, 14, 14, 140, 60, 20)
    preencher(20, 16, 28, 20, *SH); preencher(28, 16, 36, 20, *SH)
    preencher(16, 20, 20, 32, *SH); preencher(20, 20, 28, 32, *SH)
    preencher(28, 20, 32, 32, *SH); preencher(32, 20, 40, 32, *SH)
    preencher(23, 20, 25, 32, 50, 75, 155)
    preencher(44, 16, 48, 20, *SK); preencher(48, 16, 52, 20, *SK)
    preencher(40, 20, 44, 32, *SK); preencher(44, 20, 48, 32, *SK)
    preencher(48, 20, 52, 32, *SK); preencher(52, 20, 56, 32, *SK)
    preencher(44, 20, 48, 24, *SH); preencher(40, 20, 44, 24, *SH)
    preencher(48, 20, 52, 24, *SH); preencher(52, 20, 56, 24, *SH)
    preencher( 4, 16,  8, 20, *PT); preencher( 8, 16, 12, 20, *PT)
    preencher( 0, 20,  4, 32, *PT); preencher( 4, 20,  8, 32, *PT)
    preencher( 8, 20, 12, 32, *PT); preencher(12, 20, 16, 32, *PT)
    preencher( 0, 28,  4, 32, *BT); preencher( 4, 28,  8, 32, *BT)
    preencher( 8, 28, 12, 32, *BT); preencher(12, 28, 16, 32, *BT)

    return base64.b64encode(bytes(buf)).decode('utf-8')

SKIN_STEVE = gerar_skin_steve()

class Escritor:
    def __init__(self): self.partes = []
    def u8(self, v):    self.partes.append(struct.pack('B', v & 0xFF)); return self
    def u16be(self, v): self.partes.append(struct.pack('>H', v & 0xFFFF)); return self
    def i32be(self, v): self.partes.append(struct.pack('>i', v)); return self
    def u32be(self, v): self.partes.append(struct.pack('>I', v & 0xFFFFFFFF)); return self
    def i32le(self, v): self.partes.append(struct.pack('<i', v)); return self
    def i64be(self, v): self.partes.append(struct.pack('>q', v)); return self
    def u64be(self, v): self.partes.append(struct.pack('>Q', v & 0xFFFFFFFFFFFFFFFF)); return self
    def f32be(self, v): self.partes.append(struct.pack('>f', v)); return self
    def t_le(self, v):  self.partes.append(bytes([v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF])); return self
    def raw(self, b):   self.partes.append(bytes(b)); return self
    def magic(self):    self.partes.append(MAGIA); return self
    def str_(self, s):
        b = s.encode('utf-8'); self.u16be(len(b)); self.partes.append(b); return self
    def str_raw(self, b):
        b = bytes(b); self.u16be(len(b)); self.partes.append(b); return self
    def rak_ip(self, ip, porta):
        self.u8(4)
        for o in ip.split('.'): self.u8((~int(o)) & 0xFF)
        self.u16be(porta); return self
    def buf(self): return b''.join(self.partes)

class Leitor:
    def __init__(self, b): self.b = bytes(b); self.p = 0
    def left(self):   return len(self.b) - self.p
    def u8(self):     v = self.b[self.p]; self.p += 1; return v
    def u16be(self):  v = struct.unpack_from('>H', self.b, self.p)[0]; self.p += 2; return v
    def i32be(self):  v = struct.unpack_from('>i', self.b, self.p)[0]; self.p += 4; return v
    def u32be(self):  v = struct.unpack_from('>I', self.b, self.p)[0]; self.p += 4; return v
    def i64be(self):  v = struct.unpack_from('>q', self.b, self.p)[0]; self.p += 8; return v
    def u64be(self):  v = struct.unpack_from('>Q', self.b, self.p)[0]; self.p += 8; return v
    def f32be(self):  v = struct.unpack_from('>f', self.b, self.p)[0]; self.p += 4; return v
    def t_le(self):   v = self.b[self.p]|(self.b[self.p+1]<<8)|(self.b[self.p+2]<<16); self.p+=3; return v
    def bytes_(self, n): v = self.b[self.p:self.p+n]; self.p += n; return v
    def skip(self, n):   self.p += n; return self
    def str_(self):   n = self.u16be(); return self.bytes_(n).decode('utf-8', errors='replace')

MAGIA = bytes([0x00,0xFF,0xFF,0x00,0xFE,0xFE,0xFE,0xFE,0xFD,0xFD,0xFD,0xFD,0x12,0x34,0x56,0x78])
MTU_LISTA = [1492, 1464, 1400, 1200, 576]

P70 = {'LOGIN':0x8f,'PLAY_STATUS':0x90,'DISCONNECT':0x91,'BATCH':0x92,'TEXT':0x93,'START_GAME':0x95,'MOVE_PLAYER':0x9d,'CHUNK_RADIUS':0xc9}
P84_A = {'LOGIN':0x01,'PLAY_STATUS':0x02,'DISCONNECT':0x05,'RSPACK_INFO':0x06,'RSPACK_STACK':0x07,'RSPACK_RESP':0x08,'TEXT':0x07,'START_GAME':0x09,'MOVE_PLAYER':0x10,'CHUNK_RADIUS':0x3d}
P84_B = {'LOGIN':0x01,'PLAY_STATUS':0x02,'SERVER_HS':0x03,'CLIENT_HS':0x04,'DISCONNECT':0x05,'RSPACK_INFO':0x06,'RSPACK_STACK':0x07,'RSPACK_RESP':0x08,'TEXT':0x09,'START_GAME':0x0b,'MOVE_PLAYER':0x13,'CHUNK_RADIUS':0x45}

try:
    CHAVE_EC = ec.generate_private_key(ec.SECP384R1(), default_backend())
except Exception:
    CHAVE_EC = None

def pub_key_b64():
    if CHAVE_EC is None: return 'AAAA'
    return base64.b64encode(CHAVE_EC.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )).decode('utf-8')

def b64url(dados):
    if isinstance(dados, (dict, list)):
        dados = json.dumps(dados, separators=(',', ':')).encode('utf-8')
    elif isinstance(dados, str):
        dados = dados.encode('utf-8')
    return base64.urlsafe_b64encode(dados).rstrip(b'=').decode('utf-8')

def der_sig_para_raw(der):
    o = 2
    rl = der[o+1]; o += 2; rr = der[o:o+rl]; o += rl
    sl = der[o+1]; o += 2; sr = der[o:o+sl]
    ra = bytearray(48); sa = bytearray(48)
    rt = rr[1:] if rr[0]==0 else rr
    st = sr[1:] if sr[0]==0 else sr
    ra[48-len(rt):] = rt; sa[48-len(st):] = st
    return bytes(ra) + bytes(sa)

def criar_jwt(payload):
    pub = pub_key_b64()
    dados = b64url({'alg':'ES384','x5u':pub}) + '.' + b64url(payload)
    if CHAVE_EC is None: return dados + '.'
    try:
        der = CHAVE_EC.sign(dados.encode('utf-8'), ec.ECDSA(hashes.SHA384()))
        return dados + '.' + base64.urlsafe_b64encode(der_sig_para_raw(der)).rstrip(b'=').decode('utf-8')
    except Exception:
        return dados + '.'

def construir_login84(bot):
    pub = pub_key_b64()
    uuid = '00000000-0000-4000-8000-' + os.urandom(6).hex()
    agora = int(time.time())
    corrente = criar_jwt({'extraData':{'displayName':bot['nome'],'identity':uuid,'XUID':''},'identityPublicKey':pub,'nbf':agora-60,'exp':agora+86400})
    skin = criar_jwt({'ClientRandomId':bot['client_id']&0xFFFFFFFF,'ServerAddress':f"{HOST}:{PORTA}",'SkinData':SKIN_STEVE,'SkinId':'Standard_Custom','CapeData':'','SkinGeometryName':'geometry.humanoid.custom','SkinGeometry':'','DeviceOS':1,'GameVersion':'0.15.10'})
    cb = json.dumps({'chain':[corrente]}).encode('utf-8')
    sb = skin.encode('utf-8')
    raw = Escritor().i32le(len(cb)).raw(cb).i32le(len(sb)).raw(sb).buf()
    comp = zlib.compress(raw, level=7)
    return bytes([0xfe,0x01]) + Escritor().i32be(84).i32be(len(comp)).raw(comp).buf()

def construir_login70(bot):
    buf_skin = base64.b64decode(SKIN_STEVE)
    return (Escritor().u8(P70['LOGIN']).str_(bot['nome']).i32be(70).i32be(70)
               .u64be(bot['client_id']).raw(os.urandom(16))
               .str_(f"{HOST}:{PORTA}").str_('').str_('Standard_Custom')
               .str_raw(buf_skin).u8(0).buf())

def construir_batch(pkts, bot):
    interno = b''.join(struct.pack('>I', len(p)) + p for p in pkts)
    comp = zlib.compress(interno, level=7)
    if bot['proto'] >= 84:
        return bytes([0xfe,0x06]) + Escritor().i32be(len(comp)).raw(comp).buf()
    return Escritor().u8(P70['BATCH']).i32be(len(comp)).raw(comp).buf()

ARMAZEM_FRAME_MAX = 1024

def _udp_enviar(bot, buf):
    if bot['sock'] is None: return
    try: bot['sock'].sendto(buf, (HOST, PORTA))
    except Exception: pass

def _rak_frame(bot, payload, eh_split, count_split, id_split, idx_split):
    if bot['sock'] is None or bot['esta_fechando'] or tempo_terminado: return
    seq = bot['send_seq']; bot['send_seq'] += 1
    w = Escritor()
    w.u8(0x84).t_le(seq)
    w.u8(0x70 if eh_split else 0x60)
    w.u16be(len(payload) * 8)
    mi = bot['msg_index']; bot['msg_index'] += 1
    oi = bot['order_index']; bot['order_index'] += 1
    w.t_le(mi).t_le(oi).u8(0)
    if eh_split: w.u32be(count_split).u16be(id_split).u32be(idx_split)
    w.raw(payload)
    buf = w.buf()
    bot['sent_frames'][seq] = buf
    if len(bot['sent_frames']) > ARMAZEM_FRAME_MAX:
        del bot['sent_frames'][next(iter(bot['sent_frames']))]
    _udp_enviar(bot, buf)

def enviar_confiavel_ordenado(bot, payload):
    if bot['sock'] is None or bot['esta_fechando'] or tempo_terminado: return
    MAX = (bot['mtu_size'] or 1464) - 60
    if len(payload) <= MAX:
        _rak_frame(bot, payload, False, 0, 0, 0); return
    sid = bot['split_id'] & 0xFFFF; bot['split_id'] += 1
    cnt = math.ceil(len(payload) / MAX)
    for i in range(cnt):
        _rak_frame(bot, payload[i*MAX:(i+1)*MAX], True, cnt, sid, i)

def enviar_jogo(bot, pkt):
    if bot['sock'] is None or bot['esta_fechando'] or tempo_terminado: return
    enviar_confiavel_ordenado(bot, construir_batch([pkt], bot))

def enviar_ack(bot, nums):
    if bot['sock'] is None or bot['esta_fechando']: return
    sns = sorted(set(nums)); recs = []; i = 0
    while i < len(sns):
        s = e = sns[i]
        while i+1 < len(sns) and sns[i+1] == sns[i]+1: i += 1; e = sns[i]
        recs.append((s, e)); i += 1
    w = Escritor().u8(0xC0).u16be(len(recs))
    for s, e in recs:
        w.u8(1).t_le(s) if s == e else w.u8(0).t_le(s).t_le(e)
    _udp_enviar(bot, w.buf())

def lidar_nack(bot, msg):
    if bot['sock'] is None or bot['esta_fechando']: return
    try:
        r = Leitor(msg); r.skip(1); cnt = r.u16be()
        for _ in range(cnt):
            unico = r.u8(); s = r.t_le(); e = s if unico else r.t_le()
            for seq in range(s, e+1):
                f = bot['sent_frames'].get(seq)
                if f and bot['sock'] and not bot['esta_fechando']:
                    _udp_enviar(bot, f)
    except Exception: pass

def obter_ids(bot):
    if bot['proto'] < 84:
        return {'move':P70['MOVE_PLAYER'],'text':P70['TEXT'],'chunk':P70['CHUNK_RADIUS']}
    if bot['usa_variante_a']:
        return {'move':P84_A['MOVE_PLAYER'],'text':P84_A['TEXT'],'chunk':P84_A['CHUNK_RADIUS']}
    return {'move':P84_B['MOVE_PLAYER'],'text':P84_B['TEXT'],'chunk':P84_B['CHUNK_RADIUS']}

def construir_chunk_radius(bot):
    return Escritor().u8(obter_ids(bot)['chunk']).i32be(8).buf()

def construir_mover_jogador(bot):
    p = bot['pos']
    return (Escritor().u8(obter_ids(bot)['move']).i64be(bot['entity_id'])
               .f32be(p['x']).f32be(p['y']).f32be(p['z'])
               .f32be(p['yaw']).f32be(p['yaw']).f32be(p['pitch'])
               .u8(0).u8(1).buf())

def construir_chat(bot, msg):
    return Escritor().u8(obter_ids(bot)['text']).u8(1).str_(bot['nome']).str_(msg).buf()

def construir_rspack_resp(bot, status):
    rid = P84_A['RSPACK_RESP'] if bot['usa_variante_a'] else P84_B['RSPACK_RESP']
    return Escritor().u8(rid).u8(status).u16be(0).buf()

def enviar_registro(bot):
    if bot['registro_enviado'] or not CMD_REGISTRO:
        return
    bot['registro_enviado'] = True

    msg = construir_msg_registro()

    def enviar(n):
        if bot['esta_fechando'] or tempo_terminado: return
        enviar_jogo(bot, construir_chat(bot, msg))
        print(f"[{bot['nome']}] Registro #{n} -> \"{msg}\"")

    enviar(1)
    threading.Timer(0.8, lambda: enviar(2)).start()
    threading.Timer(2.0, lambda: enviar(3)).start()

def iniciar_spam(bot):
    if bot['spam_ativo'] or bot['esta_fechando']: return
    bot['spam_ativo'] = True
    bot['spam_idx'] = 0

    def loop():
        time.sleep(INTERVALO_MSG)
        while bot['spam_ativo'] and not bot['esta_fechando'] and not tempo_terminado:
            msg = MENSAGENS[bot['spam_idx'] % len(MENSAGENS)]
            bot['spam_idx'] += 1
            enviar_jogo(bot, construir_chat(bot, msg))
            print(f"[{bot['nome']}] Spam -> \"{msg}\"")
            time.sleep(INTERVALO_MSG)
        bot['spam_ativo'] = False

    threading.Thread(target=loop, daemon=True).start()

TICK_MOVIMENTO_S = 0.1
MUDANCA_MOVIMENTO_S = 3.0
PASSO_MOVIMENTO = 0.28
ALCANCE_MOVIMENTO = 22
TAXA_GRAVIDADE = 0.12

def iniciar_movimento(bot):
    if bot['movimento_ativo'] or bot['esta_fechando']: return
    bot['movimento_ativo'] = True
    ox, oy, oz = bot['pos']['x'], bot['pos']['y'], bot['pos']['z']
    st = {'dir': random.random()*math.pi*2, 'spd': PASSO_MOVIMENTO, 'velY': 0.0, 'last_dir': time.time()}

    def loop():
        while bot['movimento_ativo'] and not bot['esta_fechando'] and not tempo_terminado:
            agora = time.time()
            if agora - st['last_dir'] >= MUDANCA_MOVIMENTO_S:
                st['dir'] = random.random()*math.pi*2
                st['spd'] = PASSO_MOVIMENTO*(0.6+random.random()*0.8)
                st['last_dir'] = agora
            dx = bot['pos']['x']-ox; dz = bot['pos']['z']-oz
            if dx*dx + dz*dz > ALCANCE_MOVIMENTO*ALCANCE_MOVIMENTO:
                st['dir'] = math.atan2(oz-bot['pos']['z'], ox-bot['pos']['x'])
                st['spd'] = PASSO_MOVIMENTO*1.2
            else:
                bot['pos']['x'] += math.cos(st['dir'])*st['spd']
                bot['pos']['z'] += math.sin(st['dir'])*st['spd']
            p = bot['pos']
            if p['y'] > oy+0.05:
                st['velY'] -= TAXA_GRAVIDADE; p['y'] += st['velY']
                if p['y'] <= oy: p['y'] = oy; st['velY'] = 0.0
            elif p['y'] < oy-0.05:
                p['y'] += 0.2
                if p['y'] > oy: p['y'] = oy
            else:
                p['y'] = oy; st['velY'] = 0.0
            bot['pos']['yaw'] = ((st['dir']*180/math.pi)+90+360)%360
            enviar_jogo(bot, construir_mover_jogador(bot))
            time.sleep(TICK_MOVIMENTO_S)
        bot['movimento_ativo'] = False

    threading.Thread(target=loop, daemon=True).start()

def ao_spawnar(bot):
    global bots_conectados
    if bot['spawnado']: return
    bot['spawnado'] = True
    with lock_global:
        bots_conectados += 1
        bots_ativos.append(bot)
    p = bot['pos']
    print(f"[{bot['nome']}] Spawnado pos=({p['x']:.1f},{p['y']:.1f},{p['z']:.1f}) total={bots_conectados}/{BOTS}")

    enviar_registro(bot)
    iniciar_movimento(bot)
    iniciar_spam(bot)

def mcpe(bot, data):
    if not data or bot['esta_fechando']: return
    pid = data[0]; r = Leitor(data); r.skip(1)

    if pid == P70['PLAY_STATUS'] or pid == 0x02:
        st = r.i32be()
        nomes = {0:'Login OK',1:'Cliente velho',2:'Servidor cheio',3:'Spawnado',4:'Mundo velho',5:'Cliente novo'}
        print(f"[{bot['nome']}] PLAY_STATUS={st} ({nomes.get(st,'?')})")
        if st == 0:
            enviar_jogo(bot, construir_chunk_radius(bot))
        elif st in (1, 2):
            fechar_bot(bot)
        elif st == 3:
            ao_spawnar(bot)
        return

    if pid == 0x06 and bot['proto'] >= 84 and not bot['pack_recurso_feito'] and not bot['usa_variante_a']:
        enviar_jogo(bot, construir_rspack_resp(bot, 3)); return

    if pid == 0x07 and bot['proto'] >= 84 and not bot['pack_recurso_feito'] and not bot['usa_variante_a']:
        bot['pack_recurso_feito'] = True
        enviar_jogo(bot, construir_rspack_resp(bot, 4)); return

    if pid == 0x03 and bot['proto'] >= 84:
        enviar_jogo(bot, Escritor().u8(0x04).buf())
        enviar_jogo(bot, construir_chunk_radius(bot)); return

    if pid in (P70['START_GAME'], 0x09, 0x0b, 0x11):
        if bot['proto'] >= 84:
            bot['usa_variante_a'] = (pid == 0x09)
        try:
            r.i32be(); r.u8(); r.i32be(); r.i32be()
            bot['entity_id'] = r.i64be()
            r.i32be(); r.i32be(); r.i32be()
            bot['pos']['x'] = r.f32be()
            bot['pos']['y'] = r.f32be()
            bot['pos']['z'] = r.f32be()
            p = bot['pos']
            print(f"[{bot['nome']}] START_GAME eid={bot['entity_id']} pos=({p['x']:.1f},{p['y']:.1f},{p['z']:.1f})")
        except Exception:
            print(f"[{bot['nome']}] START_GAME recebido")
        enviar_jogo(bot, construir_chunk_radius(bot))
        if bot['spawn_fallback'] is None:
            def fallback():
                if not bot['spawnado'] and not bot['esta_fechando'] and not tempo_terminado:
                    print(f"[{bot['nome']}] Fallback spawn")
                    ao_spawnar(bot)
            t = threading.Timer(10.0, fallback); t.daemon = True; t.start()
            bot['spawn_fallback'] = t
        return

    if pid in (P70['DISCONNECT'], 0x05):
        msg = ''
        try: msg = r.str_()
        except Exception: pass
        print(f"[{bot['nome']}] Kick: \"{msg or '(sem mensagem)'}\"")
        fechar_bot(bot); return

    if pid not in bot['unknown_logged']:
        bot['unknown_logged'].add(pid)

def lidar_batch(bot, payload):
    if bot['esta_fechando']: return
    try:
        r = Leitor(payload); cl = r.i32be(); comp = r.bytes_(min(cl, r.left()))
        try: interno = zlib.decompress(comp)
        except Exception: interno = zlib.decompress(comp, -15)
        ir = Leitor(interno)
        while ir.left() >= 4:
            ln = ir.u32be()
            if ln == 0 or ln > ir.left(): break
            pkt = ir.bytes_(ln)
            mcpe(bot, pkt[1:] if pkt[0]==0xfe and len(pkt)>1 else pkt)
    except Exception: pass

def pacote_interno(bot, payload):
    if not payload or bot['esta_fechando']: return
    pid = payload[0]
    if pid == 0x00:
        if len(payload) >= 9:
            t = struct.unpack_from('>q', payload, 1)[0]
            _rak_frame(bot, Escritor().u8(0x03).i64be(t).i64be(int(time.time()*1000)).buf(), False,0,0,0)
        return
    if pid == 0x03: return
    if pid == 0x15: fechar_bot(bot); return
    if pid == 0x10: lidar_handshake_servidor(bot, payload); return
    if pid == 0xfe:
        if len(payload) < 2: return
        lidar_batch(bot, payload[2:]) if payload[1]==0x06 else mcpe(bot, payload[1:])
        return
    if pid == P70['BATCH']:               lidar_batch(bot, payload[1:]); return
    if pid == 0x06 and bot['proto'] >= 84: lidar_batch(bot, payload[1:]); return
    mcpe(bot, payload)

def analisar_pacote_dados(bot, msg):
    if bot['esta_fechando']: return
    r = Leitor(msg); r.skip(1); seq = r.t_le()
    bot['ack_queue'].append(seq)
    while r.left() > 0:
        try:
            flags = r.u8(); rel = (flags>>5)&7; eh_split = (flags>>4)&1
            bits = r.u16be(); blen = math.ceil(bits/8)
            if rel in (2,3,4,6,7): r.t_le()
            if rel in (1,3,4):     r.t_le(); r.u8()
            sc=si=sx=0
            if eh_split: sc=r.u32be(); si=r.u16be(); sx=r.u32be()
            payload = r.bytes_(blen)
            if eh_split:
                if si not in bot['split_map']: bot['split_map'][si]=[None]*sc
                bot['split_map'][si][sx] = payload
                if all(x is not None for x in bot['split_map'][si]):
                    pacote_interno(bot, b''.join(bot['split_map'][si]))
                    del bot['split_map'][si]
            else:
                pacote_interno(bot, payload)
        except Exception: break

def lidar_handshake_servidor(bot, payload):
    if bot['esta_fechando']: return
    r = Leitor(payload); r.skip(1); ping_time = 0
    try:
        v = r.u8(); r.skip(6 if v==4 else 18); r.skip(2)
        for _ in range(10): x = r.u8(); r.skip(6 if x==4 else 18)
        ping_time = r.i64be()
    except Exception: pass
    hw = Escritor().u8(0x13).rak_ip(HOST, PORTA)
    for _ in range(10): hw.u8(4).u8(0x80).u8(0xFF).u8(0xFF).u8(0xFE).u16be(0)
    hw.i64be(ping_time).i64be(int(time.time()*1000))
    _rak_frame(bot, hw.buf(), False,0,0,0)
    if bot['fase'] == 'HANDSHAKING':
        bot['fase'] = 'LOGIN'
        print(f"[{bot['nome']}] Handshake OK -> login proto {bot['proto']}")
        def do_login():
            if tempo_terminado or bot['esta_fechando']: return
            enviar_confiavel_ordenado(bot, construir_login84(bot) if bot['proto']>=84 else construir_login70(bot))
        threading.Timer(0.1, do_login).start()

def enviar_request1(bot):
    if bot['sock'] is None or bot['esta_fechando'] or tempo_terminado: return
    mtu = MTU_LISTA[bot['mtu_idx'] % len(MTU_LISTA)]; bot['mtu_size'] = mtu
    padding = max(0, mtu - 28 - 1 - 16 - 1)
    _udp_enviar(bot, Escritor().u8(0x05).magic().u8(7).raw(bytes(padding)).buf())

def fechar_bot(bot):
    if bot['esta_fechando']: return
    bot['esta_fechando'] = True
    bot['conectado'] = False
    bot['spawnado'] = False
    bot['movimento_ativo'] = False
    bot['spam_ativo'] = False
    for attr in ('spawn_fallback','mtu_retry_t','req2_retry_t'):
        t = bot.get(attr)
        if t: t.cancel(); bot[attr] = None
    sock = bot['sock']; bot['sock'] = None
    if sock:
        try: sock.close()
        except Exception: pass
    print(f"[{bot['nome']}] Desconectado")

def agendar_mtu_retry(bot):
    if bot['mtu_retry_t']: bot['mtu_retry_t'].cancel()
    def retry():
        if bot['fase'] != 'CONNECTING_1' or bot['esta_fechando'] or tempo_terminado: return
        bot['mtu_idx'] = (bot['mtu_idx']+1) % len(MTU_LISTA)
        print(f"[{bot['nome']}] Sem Reply1, MTU={MTU_LISTA[bot['mtu_idx']]}...")
        enviar_request1(bot); agendar_mtu_retry(bot)
    t = threading.Timer(3.0, retry); t.daemon=True; t.start(); bot['mtu_retry_t'] = t

def iniciar_bot(numero):
    bot = {
        'id': numero, 'nome': gerar_nome(NOME),
        'fase': 'UNCONNECTED',
        'client_id': int.from_bytes(os.urandom(8), 'big'),
        'mtu_size': MTU_LISTA[0], 'mtu_idx': 0, 'server_guid': 0,
        'send_seq': 0, 'msg_index': 0, 'order_index': 0, 'split_id': 0,
        'ack_queue': [], 'split_map': {}, 'sent_frames': {},
        'entity_id': 0, 'proto': 70, 'usa_variante_a': False,
        'pack_recurso_feito': False,
        'pos': {'x':0.,'y':64.,'z':0.,'yaw':0.,'pitch':0.},
        'spawnado': False, 'conectado': False,
        'movimento_ativo': False, 'spam_ativo': False, 'spam_idx': 0,
        'spawn_fallback': None, 'mtu_retry_t': None, 'req2_retry_t': None,
        'esta_fechando': False, 'registro_enviado': False,
        'unknown_logged': set(), 'sock': None, '_req2flip': False,
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.bind(('', 0))
    bot['sock'] = sock

    def loop_recv():
        while not bot['esta_fechando'] and not tempo_terminado:
            try:
                msg, _ = sock.recvfrom(65535)
            except BlockingIOError:
                time.sleep(0.001); continue
            except Exception:
                break
            if not msg: continue
            pid = msg[0]

            if pid == 0xC0: continue
            if pid == 0xA0: lidar_nack(bot, msg); continue
            if 0x80 <= pid <= 0x8F:
                analisar_pacote_dados(bot, msg)
                if bot['ack_queue'] and not bot['esta_fechando']:
                    enviar_ack(bot, bot['ack_queue']); bot['ack_queue'] = []
                continue

            if pid == 0x06 and bot['fase'] == 'CONNECTING_1':
                if len(msg) >= 2:
                    m = struct.unpack_from('>H', msg, len(msg)-2)[0]
                    bot['mtu_size'] = m if 576 <= m <= 1500 else 1400
                try:
                    if len(msg) >= 25: bot['server_guid'] = struct.unpack_from('>Q', msg, 17)[0]
                except Exception: pass
                bot['fase'] = 'CONNECTING_2'
                if bot['mtu_retry_t']: bot['mtu_retry_t'].cancel(); bot['mtu_retry_t'] = None
                print(f"[{bot['nome']}] Reply1 MTU={bot['mtu_size']} -> Request2")
                req2std = Escritor().u8(0x07).magic().rak_ip(HOST,PORTA).u16be(bot['mtu_size']).u64be(bot['client_id']).buf()
                req2alt = Escritor().u8(0x07).magic().rak_ip(HOST,PORTA).u64be(bot['client_id']).u16be(bot['mtu_size']).buf()
                _udp_enviar(bot, req2std); bot['_req2flip'] = False
                def send_req2():
                    if bot['fase']!='CONNECTING_2' or bot['esta_fechando']: return
                    bot['_req2flip'] = not bot['_req2flip']
                    _udp_enviar(bot, req2alt if bot['_req2flip'] else req2std)
                    t = threading.Timer(2.0, send_req2); t.daemon=True; t.start(); bot['req2_retry_t']=t
                t = threading.Timer(2.0, send_req2); t.daemon=True; t.start(); bot['req2_retry_t']=t
                continue

            if pid == 0x08 and bot['fase'] == 'CONNECTING_2':
                if bot['req2_retry_t']: bot['req2_retry_t'].cancel(); bot['req2_retry_t'] = None
                bot['fase'] = 'HANDSHAKING'
                print(f"[{bot['nome']}] Reply2 OK -> Client Connect")
                _rak_frame(bot, Escritor().u8(0x09).u64be(bot['client_id']).i64be(int(time.time()*1000)).u8(0).buf(), False,0,0,0)
                continue

            if pid == 0x1C and bot['fase'] == 'UNCONNECTED':
                try:
                    r2 = Leitor(msg); r2.skip(1+8+8+16)
                    motd = r2.bytes_(r2.u16be()).decode('utf-8', errors='replace')
                    parts = motd.split(';')
                    if len(parts) >= 3 and parts[2].isdigit():
                        p = int(parts[2])
                        if p > 0: bot['proto'] = p
                    srv = (parts[1] if len(parts)>1 else '?').strip()[:40]
                    print(f"[{bot['nome']}] Server: \"{srv}\" proto={bot['proto']}")
                except Exception: pass
                if bot['mtu_retry_t']: bot['mtu_retry_t'].cancel(); bot['mtu_retry_t'] = None
                bot['fase'] = 'CONNECTING_1'
                enviar_request1(bot); agendar_mtu_retry(bot)
                continue

    threading.Thread(target=loop_recv, daemon=True).start()

    _udp_enviar(bot, Escritor().u8(0x01).i64be(int(time.time()*1000)).magic().u64be(bot['client_id']).buf())

    ping_count = [0]
    def loop_ping():
        while bot['fase']=='UNCONNECTED' and not bot['esta_fechando'] and not tempo_terminado:
            time.sleep(0.5); ping_count[0] += 1
            if ping_count[0] >= 4:
                if bot['fase']=='UNCONNECTED':
                    print(f"[{bot['nome']}] Sem pong -> proto 70 direto")
                    bot['proto']=70; bot['fase']='CONNECTING_1'
                    enviar_request1(bot); agendar_mtu_retry(bot)
                return
            _udp_enviar(bot, Escritor().u8(0x01).i64be(int(time.time()*1000)).magic().u64be(bot['client_id']).buf())
    threading.Thread(target=loop_ping, daemon=True).start()

    def keepalive():
        while not bot['esta_fechando'] and not tempo_terminado:
            time.sleep(5.0)
            if bot['esta_fechando'] or tempo_terminado: break
            if bot['fase']=='LOGIN' or bot['spawnado']:
                _rak_frame(bot, Escritor().u8(0x00).i64be(int(time.time()*1000)).buf(), False,0,0,0)
    threading.Thread(target=keepalive, daemon=True).start()

    return bot

# REMOVIDO: função limite_tempo() - não é mais necessária

def handler_sinal(sig, frame):
    global tempo_terminado
    print('\n( BOMBC2 ) Ctrl+C — desconectando bots...')
    tempo_terminado = True
    for bot in list(bots_ativos):
        try:
            if bot['sock'] and not bot['esta_fechando']:
                _rak_frame(bot, Escritor().u8(0x15).buf(), False,0,0,0)
                threading.Timer(0.2, lambda b=bot: fechar_bot(b)).start()
            else:
                fechar_bot(bot)
        except Exception:
            fechar_bot(bot)
    time.sleep(0.5)
    print(f"( BOMBC2 ) Total conectados: {bots_conectados}")
    os._exit(0)

signal.signal(signal.SIGINT, handler_sinal)

print(f"( BOMBC2 ) Iniciando {BOTS} bot(s) - CONEXÃO INFINITA...\n")
for i in range(BOTS):
    threading.Timer(i * 0.3, lambda idx=i: iniciar_bot(idx) if not tempo_terminado else None).start()

try:
    while True: time.sleep(1)
except SystemExit:
    pass
