"""
Copyright 2026 温中志 (Wen Zhongzhi)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from ecashaddress import convert
import base58  # pip install base58
import socket
import threading
import time
import json
import os
import binascii
from hashlib import sha256
import requests
from typing import List, Dict, Any, Optional, Tuple
from queue import Queue

# ===========================
# === 用户配置区（必须修改）===
# ===========================
RPC_USER = "your_rpc_user"       # bitcoin.conf 中的 rpcuser
RPC_PASS = "your_rpc_password"   # bitcoin.conf 中的 rpcpassword
RPC_HOST = "127.0.0.1"
RPC_PORT = 8332

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 3333

# 轮询间隔（秒），建议 10-30；越短越耗 RPC
GBT_POLL_INTERVAL = 20

# extranonce: 代理分配给每个矿工的 extranonce1 字节数 (通常 4)
EXTRANONCE1_BYTES = 4
# 矿机会提供的 extranonce2 大小（默认使用 4）
EXTRANONCE2_BYTES = 4

# 如果 coinbasetxn 中没有明确的占位符，我们会在 coinbase 末尾追加 extranonces
# （多数 BCH GBT 会包含 coinbasetxn.data，并且会包含占位符）
EXTRANONCE_PLACEHOLDER = "00" * (EXTRANONCE1_BYTES + EXTRANONCE2_BYTES)
COINBASE_TAG = b"/BitcoinCash Stratum Proxy/"

# 默认支付地址（当矿工未提供时使用）
DEFAULT_PAYOUT_ADDRESS = "bitcoincash:your_default_address_here"

# 设置ASIC矿机有效share的最小难度
MIN_SHARE_DIFF = 100_000  # 全局配置，矿机提交的share难度必须大于100K

# RPC 调用超时和重试
RPC_TIMEOUT = 10
RPC_MAX_RETRIES = 3
RPC_RETRY_BACKOFF = 2  # 指数退避基数

# 日志输出开关
DEBUG = True
MAX_MINERS = 20

# ===========================
# === 全局状态（内部使用）===
# ===========================
_current_gbt: Optional[Dict[str, Any]] = None
_current_job: Optional[Dict[str, Any]] = None
_current_height: int = -1

# Manage the list of all connected miner handlers
# use thread lock to make sure same resource only changed by one thread
_miners_lock = threading.Lock()
_miners: List["StratumMinerHandler"] = []

# lock protecting GBT and job
_gbt_lock = threading.Lock()

# ===========================
# === 辅助函数（序列化/哈希/编码）===
# ===========================
def log(*args):
    if DEBUG:
        print(time.strftime('%Y-%m-%d %H:%M:%S'), "[PROXY]", *args)

def dsha256(data: bytes) -> bytes:
    """double-sha256，返回 digest bytes（big-endian order）"""
    return sha256(sha256(data).digest()).digest()

def hex_to_bytes(h: str) -> bytes:
    #return binascii.unhexlify(h)
    return binascii.unhexlify(h.strip())

def bytes_to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode('ascii')

def reverse_bytes(b: bytes) -> bytes:
    return b[::-1]

def reverse_hex(h: str) -> str:
    """字节序反转 (hex 字符串)"""
    return bytes_to_hex(hex_to_bytes(h)[::-1])

def int_to_le_hex(n: int, length: int) -> str:
    return n.to_bytes(length, 'little').hex()

def int_to_be_hex(n: int, length: int) -> str:
    return n.to_bytes(length, 'big').hex()

def varint_encode(n: int) -> str:
    if n < 0xfd:
        return int_to_le_hex(n, 1)
    elif n <= 0xffff:
        return "fd" + int_to_le_hex(n, 2)
    elif n <= 0xffffffff:
        return "fe" + int_to_le_hex(n, 4)
    else:
        return "ff" + int_to_le_hex(n, 8)

def compact_to_target(nbits_hex: str) -> int:
    """
    将 nbits (hex string, big-endian) 转换为 target (int)
    例如: "1a2b3c4d" → target = 0x2b3c4d << (8 * (0x1a - 3))
    """
    try:
        nbits_bytes = hex_to_bytes(nbits_hex)
        if len(nbits_bytes) != 4:
            return 0

        # 大端读取 32-bit
        compact = int.from_bytes(nbits_bytes, 'big')
        size = compact >> 24
        mantissa = compact & 0xFFFFFF  # 24-bit

        if size <= 3:
            target = mantissa >> (8 * (3 - size))
        else:
            target = mantissa << (8 * (size - 3))

        # 防止溢出
        if target.bit_length() > 256:
            target = (1 << 256) - 1

        return target
    except Exception as e:
        log("compact_to_target 错误:", e)
        return 0

def bits_hex_to_int(bits_hex: str) -> int:
    return int(bits_hex, 16)

def _clean_hex(s: str, length: int) -> str:
    s = str(s).strip()
    if s.startswith('0x'):
        s = s[2:]
    s = s.ljust(length, '0')[:length]
    return s

def parse_nonce_or_ntime_to_le(hex_or_dec: Optional[str], length_bytes: int) -> str:
    """
    将矿机给出的 nonce/ntime 字符串解析为 little-endian hex（长度 length_bytes*2）
    支持： hex (BE or LE), decimal string
    优先尝试解释为 hex（并转成 little-endian），再尝试 decimal
    """
    """关键修复版：强制正确处理 BE hex → LE hex"""
    if not hex_or_dec:
        return int_to_le_hex(0, length_bytes)
    
    s = str(hex_or_dec).strip()
    if s.startswith('0x'):
        s = s[2:]
    s = s.lower()
    # 强制补齐到 8 字符
    needed = length_bytes * 2
    s = s.rjust(needed, '0')[-needed:]

    # 只要是合法 hex，直接反转（不再依赖 try-except 捕获）
    if all(c in '0123456789abcdef' for c in s):
        try:
            b = binascii.unhexlify(s)
            return bytes_to_hex(b[::-1])  # BE → LE 反转
        except Exception:
            pass  # 继续走 decimal

    # decimal fallback
    try:
        n = int(s, 10)
        return int_to_le_hex(n, length_bytes)
    except Exception:
    # 最后兜底
        return int_to_le_hex(0, length_bytes)

# ==== normalization nbits_be ====
def normalize_nbits_be(bits: Any) -> str:
    """Convert bits (int or str) to 8-character hex big-endian"""
    if isinstance(bits, int):   # judge whether bits is int type
        return int_to_be_hex(bits, 4)   # transfer bits to 4 Bytes Hex big-endian string
    s = str(bits).strip()   # remove all space characters at both ends of the string
    if s.startswith("0x"):  # if string start with 0x, remove the 0x
        s = s[2:]
    # if all content of bits string are hex characters
    if all(c in '0123456789abcdefABCDEF' for c in s):
        if len(s) != 8:
            raise ValueError(f"Invalid bits length: {len(s)} (must be 8 characters)")
        return s.lower()   # convert the processed string to all lowercase and return it

# =====================================
# === RPC encapsulation (with retry)===
# =====================================
# '= None' means List is optional params
def rpc_call(method: str, params: Optional[List[Any]] = None) -> Optional[Any]:
    url = f"http://{RPC_HOST}:{RPC_PORT}"   # f key word is mean format the string
    headers = {"content-type": "application/json"}
    payload = {"jsonrpc": "2.0", "id": "proxy", "method": method, "params": params or []}
    attempt = 0
    while attempt < RPC_MAX_RETRIES:
        try:
            resp = requests.post(url, json=payload, headers=headers, auth=(RPC_USER, RPC_PASS), timeout=RPC_TIMEOUT)
            # requests.post(url, json, headers, auth, timeout)
            resp.raise_for_status()     # If there is an HTTP error, throw an exception.      
            data = resp.json()
            if data.get('error'):
                # resp.json() will put json into dict, key is error or result. if error != null, this function will return None
                log(f"RPC error for {method}:", data['error'])
                return None
            return data.get('result')   # result object should be the whole block template data
        except Exception as e:
            attempt += 1
            log(f"RPC call {method} attempt {attempt} failed:", e)
            time.sleep(RPC_RETRY_BACKOFF ** (attempt - 1))
    log(f"RPC call {method} failed after {RPC_MAX_RETRIES} attempts.")
    return None

# ===========================
# === GBT -> Job Conversion and Broadcast ===
# ===========================
def _encode_height_to_coinbase(height: int) -> str:
    """Encode the BIP34 block-height push used at the start of scriptSig."""
    if height < 0:
        raise ValueError("block height must be non-negative")

    if height == 0:
        encoded = b""
    else:
        encoded_bytes = bytearray()
        value = height
        while value:
            encoded_bytes.append(value & 0xff)
            value >>= 8
        if encoded_bytes[-1] & 0x80:
            encoded_bytes.append(0)
        encoded = bytes(encoded_bytes)

    if len(encoded) > 75:
        raise ValueError("block height encoding is unexpectedly large")
    return bytes([len(encoded)]).hex() + encoded.hex()

def _build_minimal_coinbase_tx(height_bytes_hex: str) -> str:
    # A minimal coinbase tx, used only in the extreme case where the node does not return coinbasetxn.data.
    # this is unused function, just for reference
    version = "01000000"
    tx_in_count = "01"
    prev_out = "00" * 32 + "ffffffff"
    script_hex = height_bytes_hex + "00"
    script_len = varint_encode(len(bytes.fromhex(script_hex)))
    seq = "ffffffff"
    tx_out_count = "01"
    value = (0).to_bytes(8, 'little').hex()
    pk_script = "51"  # OP_TRUE
    pk_script_len = varint_encode(len(bytes.fromhex(pk_script)))
    lock_time = "00000000"
    return version + tx_in_count + prev_out + script_len + script_hex + seq + tx_out_count + value + pk_script_len + pk_script + lock_time

def build_coinbase_1(height: int, coinbase_aux: Optional[Dict[str, Any]] = None) -> str:
    """
    Build the transaction prefix before extranonce1/extranonce2.

    The miner constructs the full transaction as:
    coinb1 + extranonce1 + extranonce2 + coinb2.
    01000000                     version
    01                           input_count
    00...00ffffffff              null_prevout fixed by 32 bytes "00" txid + 4 bytes "ffffffff" vout 
    size of coinbase script      include script length and extranonce1 + extranonce2 size
    script_prefix                height_push + COINBASE_TAG
    """
    height_push = bytes.fromhex(_encode_height_to_coinbase(height))
    aux_data = b""
    for value in (coinbase_aux or {}).values():
        if value:
            aux_data += bytes.fromhex(str(value))

    script_prefix = height_push + aux_data + COINBASE_TAG
    extranonce_size = EXTRANONCE1_BYTES + EXTRANONCE2_BYTES
    script_sig_size = len(script_prefix) + extranonce_size
    if not 2 <= script_sig_size <= 100:
        raise ValueError(
            f"coinbase scriptSig size {script_sig_size} is outside consensus limits"
        )

    version = int_to_le_hex(2, 4)
    input_count = varint_encode(1)
    null_prevout = ("00" * 32) + "ffffffff"
    script_length = varint_encode(script_sig_size)
    return version + input_count + null_prevout + script_length + script_prefix.hex()

def _address_to_script_pubkey(payout_address: str) -> str:
    """
    P2PKH
    - 76a914
    - <20-byte hash160>
    - 88ac
    
    P2SH
    - a914
    - <20-byte script hash>
    - 87
    """
    if not isinstance(payout_address, str):
        raise ValueError("payout address must be a string")

    address = payout_address.strip()
    if not address:
        raise ValueError("payout address must not be empty")

    # CashAddr is case-insensitive only when the whole address uses one case.
    # Normalize it because mining software commonly omits "bitcoincash:".
    if ':' in address or address[0].lower() in ('q', 'p'):
        if address.lower() != address and address.upper() != address:
            raise ValueError("CashAddr must not mix uppercase and lowercase")

        address = address.lower()
        if ':' not in address:
            address = 'bitcoincash:' + address
        elif not address.startswith('bitcoincash:'):
            raise ValueError("only Bitcoin Cash mainnet CashAddr is supported")

    try:
        legacy = convert.to_legacy_address(address)
    except Exception as e:
        raise ValueError(f"invalid Bitcoin Cash payout address: {payout_address}") from e

    try:
        decoded = base58.b58decode_check(legacy)
    except Exception as e:
        raise ValueError(f"invalid legacy payout address: {payout_address}") from e

    if len(decoded) != 21:
        raise ValueError("payout address payload must contain a 20-byte hash")

    version = decoded[0]
    payload_hex = decoded[1:].hex()
    if version == 0x00:
        return "76a914" + payload_hex + "88ac"
    if version == 0x05:
        return "a914" + payload_hex + "87"
    raise ValueError(
        f"unsupported payout address network/version 0x{version:02x}; "
        "Bitcoin Cash mainnet address required"
    )


def _validated_payout_address(payout_address: str) -> str:
    """Return a trimmed usable address, raising ValueError when it is invalid."""
    address = payout_address.strip()
    _address_to_script_pubkey(address)
    return address


def build_coinbase_2(payout_address: str, coinbase_value: int) -> str:
    """
    Build the transaction suffix after extranonce1/extranonce2.
    ffffffff            sequence, fixed value
    01                  output_count
    1a6d291200000000    block reward
    script_pubkey
    00000000            lock_time, no lock fixed at 00000000
    """
    if not 0 < coinbase_value <= 0xffffffffffffffff:
        raise ValueError("coinbase value must be a positive uint64")

    script_pubkey = _address_to_script_pubkey(payout_address)
    sequence = "ffffffff"
    output_count = varint_encode(1)
    output = (
        int_to_le_hex(coinbase_value, 8)
        + varint_encode(len(bytes.fromhex(script_pubkey)))
        + script_pubkey
    )
    lock_time = "00000000"
    return sequence + output_count + output + lock_time
    
# 计算从 coinbase 到 root 的路径
def _compute_merkle_branch(coinbase_hash_be: bytes, tx_hashes_be: List[bytes]) -> List[str]:
    """
    计算从 coinbase 到 merkle root 的路径（不包含 coinbase 本身）
    返回 BE hex 字符串列表
    
    hashes = [coinbase_hash_be] + tx_hashes_be
    branch = []
    i = 0  # coinbase index
    while len(hashes) > 1:
        if i % 2 == 1:
            left = hashes[i - 1]
            right = hashes[i]
        else:
            left = hashes[i]
            right = hashes[i + 1] if i + 1 < len(hashes) else hashes[i]
        combined = left + right
        parent = dsha256(combined)
        branch.append(bytes_to_hex(right if i % 2 == 0 else left))
        # 更新 hashes
        new_hashes = []
        for j in range(0, len(hashes), 2):
            l = hashes[j]
            r = hashes[j + 1] if j + 1 < len(hashes) else l
            new_hashes.append(dsha256(l + r))
        hashes = new_hashes
        # 更新 i
        i = i // 2
    return branch
    """
    hashes = [coinbase_hash_be] + tx_hashes_be
    branch: List[str] = []
    index = 0  # coinbase index 0
    while len(hashes) > 1:
        if index % 2 == 1:
            sibling = hashes[index - 1]
        else:
            sibling = hashes[index + 1] if index + 1 < len(hashes) else hashes[index]
        branch.append(bytes_to_hex(sibling))
        # 构建下一层
        new_hashes: List[bytes] = []
        for j in range(0, len(hashes), 2):
            l = hashes[j]
            r = hashes[j + 1] if j + 1 < len(hashes) else hashes[j]
            new_hashes.append(dsha256(l + r))
        hashes = new_hashes
        index = index // 2
    return branch
    
def build_job_from_gbt(gbt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        # 1) header components, version
        version = int(gbt.get('version', 0))    # example, RPC version = 536870912, Stratum V1 format is 20000000
        # Stratum require the big end (hex) to be used for display
        version_be = int_to_be_hex(version, 4)  # 20000000

        # RPC previous block hash:          000000000000000000000da8aa8662f051cd0fec6eeca157eff33ea207923ec3
        # the hash notify to ASIC miner:    07923ec3eff33ea26eeca15751cd0fecaa8662f000000da80000000000000000
        # Convert RPC hash to Stratum V1 prevhash format
        prevhash_rpc = str(gbt.get('previousblockhash', ''))
        if len(prevhash_rpc) != 64:
            raise ValueError("GBT previousblockhash must be 32 bytes")
        words = [prevhash_rpc[i:i+8] for i in range(0, 64, 8)]
        prevhash_be = ''.join(reversed(words))

        # bits: for example "180170da"
        # bits = gbt.get('bits')
        # nbits_be = normalize_nbits_be(bits) # unused function
        bits = gbt.get('bits', '')
        nbits_be = bits

        # curtime -> ntime (int -> 4 byte BE hex)
        curtime = int(gbt.get('curtime', int(time.time())))
        ntime_be = int_to_be_hex(curtime, 4)

        # 2) coinbase deal: Bitcoin can use coinbasetxn.data, Bitcoincash doesn't support coinbasetxn.data 
        # the bitcoin coinbase will be developed in feature
        coinb1 = ''
        coinb2 = ''

        # there is no coinbasetxn in bitcoincash blocktemplate, coinbase should be manually created by proxy
        height = gbt.get('height')
        coinbase_value = gbt.get('coinbasevalue', 0)
        if height is None or coinbase_value == 0:
            return None
        # 使用默认地址或配置地址
        coinb1 = build_coinbase_1(height, gbt.get('coinbaseaux'))
        coinb2 = build_coinbase_2(DEFAULT_PAYOUT_ADDRESS, coinbase_value)
        placeholder_found = False

        transactions = gbt.get('transactions', [])
        coinbase_tx_hex = coinb1 + EXTRANONCE_PLACEHOLDER + coinb2
        coinbase_hash_be = dsha256(hex_to_bytes(coinbase_tx_hex))

        tx_hashes_be: List[bytes] = []
        for tx in transactions:
            if tx.get('data'):
                # 使用 raw tx data 计算内部 node bytes（保持与 coinbase 同样的内部表示）
                tx_hashes_be.append(dsha256(hex_to_bytes(tx['data'])))
            elif tx.get('hash'):
                # RPC 提供的 hash/txid 是 BE hex —— 将其反转为内部 bytes 表示
                tx_hashes_be.append(reverse_bytes(hex_to_bytes(tx['hash'])))  # FIXED
        merkle_branch = _compute_merkle_branch(coinbase_hash_be, tx_hashes_be)

        # 4) extranonce1 由代理生成并写入job（每个矿机仍会覆盖自己的extranonce1）
        # 这里生成一个 job-level extranonce1，以确保coinbase模板能包含至少一个代理extranonce1占位
        extranonce1 = os.urandom(EXTRANONCE1_BYTES).hex()
        extranonce2_size = EXTRANONCE2_BYTES

        job_id = f"{int(time.time())}_{prevhash_be[-8:]}"

        job = {
            "job_id": job_id,
            "gbt": gbt,
            "prevhash_be": prevhash_be,
            "version_be": version_be,
            "nbits_be": nbits_be,
            "ntime_be": ntime_be,
            "coinb1": coinb1,
            "coinb2": coinb2,
            "coinbase_value": coinbase_value,
            "merkle_branch": merkle_branch,
            "extranonce1": extranonce1,
            "extranonce2_size": extranonce2_size,
            "placeholder_found": placeholder_found,  # MODIFIED
        }
        return job
    except Exception as e:
        log("构建 job 失败:", e)
        return None

def broadcast_job_to_miners(job: Dict[str, Any]):
    """Broadcast the job to all subscribed and authorized mining machines (thread safe)"""
    with _miners_lock:
        miners_copy = list(_miners)
    for m in miners_copy:
        try:
            m.send_job(job)
        except Exception as e:
            log("Broadcast job to mining machine failed, remove mining machine:", e)
            try:
                m.close()
            except:
                pass

# ======================================
# === GBT Polling thread (background)===
# ======================================
def gbt_poller():
    global _current_gbt, _current_job, _current_height
    log("GBT polling start, Interval:", GBT_POLL_INTERVAL, "seconds")
    last_txids = None
    while True:
        try:
            # BCHN does not support SegWit template negotiation.
            gbt = rpc_call("getblocktemplate")
            if not gbt:
                time.sleep(GBT_POLL_INTERVAL)
                continue

            height = gbt.get('height', -1)  # if can't get valid height value, return -1
            # get txid data, (in order to check the mempool update), txids = ("txid1", "txid2", "txid3",...)
            txids = tuple(tx.get('txid') for tx in gbt.get('transactions', []))

            need_broadcast = False
            reason = ""
            with _gbt_lock:
                if _current_gbt is None:
                    need_broadcast = True
                    reason = "initial GBT"
                elif gbt.get('previousblockhash') != _current_gbt.get('previousblockhash'):
                    need_broadcast = True
                    reason = f"detected new block, height is {height}"
                elif txids != last_txids:
                    need_broadcast = True
                    reason = f"detected Mempool changed, tx_count={len(txids)}"
                elif gbt.get('coinbasevalue') != _current_gbt.get('coinbasevalue'):
                    need_broadcast = True
                    reason = "detected coinbasevalue changed"

                # update cache
                if need_broadcast:
                    _current_gbt = gbt  # store new gbt dict data to _current_gbt
                    _current_job = build_job_from_gbt(gbt)
                    _current_height = height
                    last_txids = txids

            if need_broadcast and _current_job:
                log("boardcast new job to ASIC:", reason, "height=", height, "txs=", len(txids))
                broadcast_job_to_miners(_current_job)
            time.sleep(GBT_POLL_INTERVAL)
        except Exception as e:
            log("GBT polling exception", e)
            time.sleep(GBT_POLL_INTERVAL)

# ===========================
# === Stratum Miner Handler ===
# ===========================
class StratumMinerHandler(threading.Thread):
    """
    each miner is connected to one Handler thread (Simplified Stratum Protocol).
    support:
      - mining.subscribe / mining.extranonce.subscribe
      - mining.authorize
      - mining.submit
      - proxy mining.notify to ASIC (base on _current_job)
    """
    def __init__(self, conn: socket.socket, addr: Tuple[str, int]):
        super().__init__(daemon=True)
        # for example, conn=<socket>, addr=('192.168.1.100', 40231)
        self.conn = conn
        self.addr = addr
        self.running = True

        # Miner status
        self.subscribed = False
        self.authorized = False
        self.worker_name = "unknown"
        self.payout_address = DEFAULT_PAYOUT_ADDRESS
        self.current_coinb2: Optional[str] = None
        
        self.difficulty = 1
        self.version_rolling = False
        self.version_rolling_mask = "1fffe000"

        # assign an extranonce1 for ASIC miner, miner will caculate the double hash of 'coinb1 + extranonce1 + extranonce1 + coinb2'
        self.extranonce1 = os.urandom(EXTRANONCE1_BYTES).hex()
        self.extranonce2_size = EXTRANONCE2_BYTES

        # assign the job id (string)
        self.current_job_id: Optional[str] = None
        
        # use fifo to put and get the sumbit data of ASIC miner
        self.submit_queue = Queue(maxsize=1000)
        self.start_submit_worker()  # Start the submit processing thread
        
        # socket read buffer
        self._buffer = ""
        self.conn.settimeout(30)
        
        # register
        with _miners_lock:
            _miners.append(self)

    def run(self):
        log("Miner IP ", self.addr)
        try:
            while self.running:
                try:
                    data = self.conn.recv(8192)
                except socket.timeout:
                    continue
                except Exception:
                    break
                if not data:
                    break
                try:
                    text = data.decode(errors='ignore')
                except:
                    text = ''
                self._buffer += text
                while '\n' in self._buffer:
                    line, self._buffer = self._buffer.split('\n', 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        msg = json.loads(line)
                    except Exception as e:
                        log("Invalid JSON from a miner:", e)
                        continue
                    try:
                        self.handle_message(msg)
                    except Exception as e:
                        log("Handling miner message anomalies:", e)
        finally:
            self.close()
            log("miner disconnected:", self.addr)

    def close(self):
        self.running = False
        
        # clear queue
        while not self.submit_queue.empty():
            try:
                self.submit_queue.get_nowait()
                self.submit_queue.task_done()
            except:
                break
            
        try:
            with _miners_lock:
                if self in _miners:
                    _miners.remove(self)
        except:
            pass
        try:
            self.conn.close()
        except:
            pass

    # -----------------------
    # --- send / response function---
    # -----------------------
    def send_json(self, obj: Dict[str, Any]):
        """Send JSON messages uniformly, with compressed format + ensure \n"""
        try:
            # compress JSON: remove spaces to reduce file size
            data = (json.dumps(obj, separators=(',', ':')) + '\n').encode('utf-8')
            self.conn.sendall(data)
        except Exception as e:
            log("Failed to send to miner:", e)
            self.close()
        
    def send_subscription_response(self, req_id):
        # Stratum standard: return extranonce1 and extranonce2_size
        resp = {
            "id": req_id,
            "result": [
                [
                    ["mining.set_difficulty", "1"],
                    ["mining.notify", "1"]
                ],
                self.extranonce1,
                self.extranonce2_size
            ],
            "error": None
        }
        self.subscribed = True
        self.send_json(resp)
        
    def send_set_difficulty(self, difficulty):
        self.difficulty = difficulty

        self.send_json({
            "id": None,
            "method": "mining.set_difficulty",
            "params": [difficulty]
        })
        
    def send_set_extranonce(self):
        self.send_json({
            "id": None,
            "method": "mining.set_extranonce",
            "params": [
                self.extranonce1,
                self.extranonce2_size
            ]
        })
        
    def send_configure_response(self, req_id, params):
        extensions = []
        options = {}

        if len(params) >= 1:
            extensions = params[0]

        if len(params) >= 2:
            options = params[1]

        result = {}

        if "version-rolling" in extensions:
            self.version_rolling = True

            requested_mask = options.get(
                "version-rolling.mask",
                self.version_rolling_mask
            )

            result["version-rolling"] = True
            result["version-rolling.mask"] = requested_mask

        self.send_json({
            "id": req_id,
            "result": result,
            "error": None
        })

    def send_authorize_response(self, req_id, ok=True):
        resp = {"id": req_id, "result": ok, "error": None}
        if ok:
            self.authorized = True
        self.send_json(resp)

    def send_job(self, job: Dict[str, Any]):
        """
        将 job 发送给矿机 (mining.notify)
        Stratum mining.notify 参数 (简化)：
        [job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs]
        注意：不同矿机固件对 coinb1/coinb2 解析敏感，下面采取较保守的处理：
          - 若 job 中 coinb1/coinb2 是模板（包含占位符），将把代理的 extranonce1 插入 coinb1
          - 若 coinb1 是完整 coinbase（无占位符），则 coinb1 保持原样，coinb2 为空
        """
        if not job:
            return
        # 下发难度（solo 挖矿用网络难度）
        difficulty = MIN_SHARE_DIFF  # 或从 nbits 计算
        diff_msg = {"id": None, "method": "mining.set_difficulty", "params": [difficulty]}
        self.send_json(diff_msg)

        # 延迟 50ms 避免粘包
        time.sleep(0.05)
        
        # 生成每个矿机专属 coinb1（包含矿机的 extranonce1）
        coinb1 = job.get('coinb1', '')
        coinbase_value = int(job.get('coinbase_value', 0))
        try:
            coinb2 = build_coinbase_2(self.payout_address, coinbase_value)
        except ValueError as e:
            log(
                f"Miner {self.addr} payout address is unusable, "
                f"falling back to default address: {e}"
            )
            self.payout_address = _validated_payout_address(DEFAULT_PAYOUT_ADDRESS)
            coinb2 = build_coinbase_2(self.payout_address, coinbase_value)
        self.current_coinb2 = coinb2

        # 如果 coinb1 中包含占位符 (EXTRANONCE_PLACEHOLDER)，则替换为代理extranonce1（job-level或conn-level）
        placeholder = EXTRANONCE_PLACEHOLDER
        extranonce2_placeholder = '00' * self.extranonce2_size

        # 确保 miner 收到的 coinb1 中包含 extranonce1 的位置
        if placeholder and job.get('placeholder_found', False) and placeholder in coinb1:
            coinb1_filled = coinb1.replace(placeholder, self.extranonce1 + extranonce2_placeholder, 1)
        else:
            # 无占位符：coinb1 已完整，不要追加 extranonce1
            coinb1_filled = coinb1

        full_coinb_hex = coinb1_filled + coinb2
        # 长度校验
        if len(full_coinb_hex) < 100 or len(full_coinb_hex) > 5000:
            log(f"警告: 下发 coinbase 长度异常 len={len(full_coinb_hex)} job_id={job.get('job_id')}")
        jid = job.get('job_id')
        self.current_job_id = jid

        branch = job.get('merkle_branch', [])
        if len(branch) > 20:
            log(f"merkle_branch 过长 {len(branch)}，截断")
            #branch = branch[:20]
        
        params = [
            jid,
            job.get('prevhash_be'),
            coinb1_filled,
            coinb2 or "",
            branch,  # 已截断的安全 branch
            job.get('version_be'),
            job.get('nbits_be'),
            job.get('ntime_be'),
            False  # clean_jobs=False
        ]
        notify = {"id": None, "method": "mining.notify", "params": params}
        self.send_json(notify)
        log(f"下发 job -> miner {self.addr}, job_id={jid}, coinb1_len={len(coinb1_filled)}, coinb2_len={len(coinb2)}")

    def start_submit_worker(self):
        t = threading.Thread(
            target=self.submit_worker,
            daemon=True
        )
        t.start()

    def submit_worker(self):
        while True:
            item = self.submit_queue.get()  # if no data put into self.submit_queue, thread flow will block in here

            try:
                self.handle_submit(*item)
            except Exception as e:
                log("submit worker error:", e)

            self.submit_queue.task_done()
            
    # -----------------------
    # --- Proxy receive the message from ASIC miner ---
    # -----------------------
    def handle_message(self, msg: Dict[str, Any]):
        method = msg.get('method')
        req_id = msg.get('id')
        params = msg.get('params', [])
        if method == "mining.subscribe":
            self.send_subscription_response(req_id)
        elif method == "mining.extranonce.subscribe":
            # A simple implementation would be to return true directly.
            self.send_json({"id": req_id, "result": True, "error": None})
        elif method == "mining.configure":
            self.send_configure_response(req_id, params)
        elif method == "mining.suggest_difficulty":
            self.send_json({"id": req_id, "result": True, "error": None})
        elif method == "mining.multi_version":
            self.send_json({"id": req_id, "result": True, "error": None})
        elif method == "mining.authorize":
            full_worker = params[0] if params else "unknown"
            # Address resolution: Supports user.worker, user, or address.
            parts = str(full_worker).split('.', 1)
            submitted_address = parts[0]
            try:
                address = _validated_payout_address(submitted_address)
            except ValueError as e:
                log(
                    f"Miner {self.addr} submitted invalid payout address "
                    f"{submitted_address!r}; using default address: {e}"
                )
                address = _validated_payout_address(DEFAULT_PAYOUT_ADDRESS)

            self.payout_address = address
            self.worker_name = parts[1] if len(parts) > 1 else ""
            self.send_authorize_response(req_id, ok=True)

            self.send_set_difficulty(1)
            self.send_set_extranonce()

            # If the current job already exists after subscription, it will be delivered immediately.
            with _gbt_lock:
                if _current_job:
                    self.send_job(_current_job)
        elif method == "mining.submit":
            # params: [workername, job_id, extranonce2, ntime, nonce] or [workername, job_id, extranonce2, ntime, nonce, version] 
            # if the elements are more than 5, how to deal with?
            worker = params[0]
            job_id = params[1]
            extranonce2 = params[2]
            ntime_hex = params[3]
            nonce_hex = params[4]
            version_bits = params[5] if len(params) > 5 else None
            
            try:
                self.submit_queue.put((req_id, worker, job_id, extranonce2, ntime_hex, nonce_hex, version_bits))
            except Exception as e:
                log("Failed to queue submit:", e)
        else:
            # unknown meth, default return ok
            self.send_json({"id": req_id, "result": False, "error": [20,"Unknown method",None]})

    # -----------------------
    # --- 提交处理 (可能较慢) ---
    # -----------------------
    def handle_submit(
        self,
        req_id,
        worker,
        job_id,
        extranonce2,
        ntime_hex,
        nonce_hex,
        version_bits=None,
    ):
        """
        1. 验证 job_id
        2. 拼接 extranonce（不重构 coinbase）
        3. 计算 merkle root（优先用 hash）
        4. 构造 BE 区块头 + 完整区块
        5. 验证难度 + submitblock
        """
    # ==================== 6. handle_submit（核心） ====================
        try:
            with _gbt_lock:
                job = _current_job
                gbt = _current_gbt
            if not job or job_id != job.get('job_id'):
                self.send_json({"id": req_id, "result": False, "error": [21, "Stale", None]})
                return

            # ---------- 1. coinbase ----------
            coinb1 = job.get('coinb1', '')
            coinb2 = self.current_coinb2
            if not coinb2:
                coinb2 = build_coinbase_2(
                    self.payout_address,
                    int(job.get('coinbase_value', 0)),
                )
            ex2 = (extranonce2 or '').rjust(self.extranonce2_size*2, '0')[:self.extranonce2_size*2]

            if job.get('placeholder_found', False) and EXTRANONCE_PLACEHOLDER in coinb1:
                coinbase_hex = coinb1.replace(EXTRANONCE_PLACEHOLDER, self.extranonce1 + ex2, 1) + coinb2
            else:
                #coinbase_hex = coinb1 + ex2  # 只加 ex2，不要加 extranonce1！
                coinbase_hex = coinbase_hex = coinb1 + self.extranonce1 + ex2 + coinb2

            # ---------- 2. merkle ----------
            """
            leaves_be = [dsha256(hex_to_bytes(coinbase_hex))]
            for tx in gbt.get('transactions', []):
                h = tx.get('hash') or tx.get('txid')
                if h:
                    leaves_be.append(hex_to_bytes(h))
            """
            leaves_be: List[bytes]  = [dsha256(hex_to_bytes(coinbase_hex))]
            for tx in gbt.get('transactions', []):
                if tx.get('data'):
                    leaves_be.append(dsha256(hex_to_bytes(tx['data'])))
                elif tx.get('hash'):
                    # RPC hash is BE hex -> convert to internal bytes by reversing
                    leaves_be.append(reverse_bytes(hex_to_bytes(tx['hash'])))  # FIXED
            merkle_root_be = _build_merkle_root_be(leaves_be)

            # 用 branch 验证 merkle root 一致性
            try:
                # 构造 merkle root from branch
                h = dsha256(hex_to_bytes(coinbase_hex))
                for mh in job.get('merkle_branch', []):
                    h = dsha256(h + hex_to_bytes(mh))
                if h != merkle_root_be:
                    log("警告: merkle_branch 计算与 build_merkle_root_be 不一致", worker, job_id)
            except Exception as e:
                log("merkle 分支校验异常:", e)
            #version_le = int_to_le_hex(gbt.get('version', 0), 4)
            version_le = reverse_hex(job['version_be'])
            prevhash_le    = reverse_hex(job.get('prevhash_be'))  # BE hex → LE hex

            merkle_root_be_hex = bytes_to_hex(merkle_root_be)  # BE bytes → BE hex
            merkle_root_le = reverse_hex(merkle_root_be_hex)  # BE hex → LE hex
            ntime_le = parse_nonce_or_ntime_to_le(ntime_hex, 4)
            nbits_le = reverse_hex(job.get('nbits_be'))  # BE hex → LE hex
            #ntime_le = reverse_hex((ntime_hex or '').rjust(8, '0')[:8])# BE hex → LE hex
            #nonce_le = reverse_hex((nonce_hex or '').rjust(8, '0')[:8])# BE hex → LE hex
            nonce_le = parse_nonce_or_ntime_to_le(nonce_hex, 4)  # note: parse here too
            
            header_le = (
                version_le + prevhash_le + merkle_root_le +
                ntime_le + nbits_le + nonce_le
            )
            header_le_bytes = hex_to_bytes(header_le)

            header_hash_le_bytes = dsha256(header_le_bytes)

            # 更直接：header_hash_int 使用 little-endian 内部 bytes
            header_hash_int = int.from_bytes(header_hash_le_bytes, 'little')  # FIXED

            # network target (传入 job['nbits_be']，big-endian hex)
            network_target = compact_to_target(job.get('nbits_be'))
            if network_target == 0:
                self.send_json({"id": req_id, "result": False, "error": [23, "Invalid target", None]})
                return

            # share difficulty
            share_diff = (1 << 256) // (header_hash_int + 1)  # MODIFIED: use 1<<256

            # 1. 难度太低 → reject
            if share_diff < MIN_SHARE_DIFF:
                self.send_json({"id": req_id, "result": False, "error": [25, "Low diff", None]})
                log(f"拒绝 share: diff={share_diff} (未达最小提交难度 {MIN_SHARE_DIFF}，不上报)")
                return

            # 2. 达到网络难度 → submitblock
            if header_hash_int <= network_target:
                # 构造完整区块并提交
                txs = [coinbase_hex]
                for tx in gbt.get('transactions', []):
                    if tx.get('data'):
                        txs.append(tx['data'])
                if gbt.get('default_witness_commitment'):
                    txs.append(gbt['default_witness_commitment'])

                block_bytes = hex_to_bytes(header_le)  # 注意: 用 header_le
                block_bytes += hex_to_bytes(varint_encode(len(txs)))
                for t in txs:
                    block_bytes += hex_to_bytes(t)

                result = rpc_call("submitblock", [bytes_to_hex(block_bytes)])
                accepted = result is None
                self.send_json({"id": req_id, "result": accepted, "error": None if accepted else [22, str(result), None]})
                log(f"区块提交: {'成功' if accepted else '失败'} share_diff={share_diff} hash={header_hash_int:064x}")
            else:
                # 3. 达到 MIN_SHARE_DIFF 但未达网络难度 → accept 但不上报
                self.send_json({"id": req_id, "result": True, "error": None})
                log(f"接受 share: diff={share_diff} (未达网络难度，不上报)")
            return
        except Exception as e:
            log("处理 submit 异常:", e)
            self.send_json({"id": req_id, "result": False, "error": [23, "Internal proxy error", None]})

# ===========================
# === Merkle 核心实现（big-endian node bytes）===
# ===========================
def _build_merkle_root_be(leaves_be: List[bytes]) -> bytes:
    """
    标准 Merkle Tree 构造（big-endian hash）
    输入：所有交易的 double-sha256 hash（BE bytes）
    输出：merkle root（BE bytes）

    if not leaves_be:
        return b'\x00' * 32
    nodes = leaves_be[:]
    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])  # 奇数时复制最后一个
        next_level = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i + 1]
            combined = left + right
            next_level.append(dsha256(combined))
        nodes = next_level
    return nodes[0]
    """
    """根据交易 hash 列表计算 Merkle root（返回 big-endian bytes）"""
    hashes = leaves_be.copy()
    if not hashes:
        return b'\x00' * 32
    while len(hashes) > 1:
        new_hashes: List[bytes] = []
        for i in range(0, len(hashes), 2):
            left = hashes[i]
            right = hashes[i + 1] if i + 1 < len(hashes) else hashes[i]
            new_hashes.append(dsha256(left + right))
        hashes = new_hashes
    return hashes[0]
    
# ===========================
# === Stratum Main service loop ===
# ===========================
def start_stratum_server(listen_host: str, listen_port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((listen_host, listen_port))
    sock.listen(100)
    log(f"Stratum proxy listen {listen_host}:{listen_port}")
    try:
        while True:
            # for example, conn=<socket>, addr=('192.168.1.100', 40231)
            conn, addr = sock.accept()  # if don't have new TCP socket, code flow will block in here
            
            with _miners_lock:
                if len(_miners) >= MAX_MINERS:
                    log("ASIC Maximum number of connections reached, connection rejected.", addr)
                    try:
                        conn.close()
                    except:
                        pass
                    continue
                
            handler = StratumMinerHandler(conn, addr)
            handler.start()
    except KeyboardInterrupt:
        log("received the exit signal, shut down the server.")
    finally:
        try:
            sock.close()
        except:
            pass
            
def main():
    if RPC_USER == "your_rpc_user" or RPC_PASS == "your_rpc_password":
        print("Please configure RPC_USER and RPC_PASS (RPC user/password in bitcoin.conf) at the top of the script first")
        exit(1)
    
    # 'daemon=True' means if main thread is end, this child Thread will be killed.
    poller_thread = threading.Thread(target=gbt_poller, daemon=True)
    poller_thread.start()   # run child thread gbt_poller   

    start_stratum_server(LISTEN_HOST, LISTEN_PORT)  # run main thread start_stratum_server
    
# ===========================
# === mainloop entry ===
# ===========================
# If this Python script is run standalone, the value of __name__ will be equal to __main__, and main() will running
if __name__ == "__main__":
    main()
