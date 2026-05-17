"""
client.py – Encrypted Messaging Client
=======================================
Anëtari 2: Client Application

Përgjegjësitë:
  - Lidhja me serverin nëpërmjet TCP socket
  - RSA key-exchange me serverin
  - Enkriptim i mesazheve me çelësin publik të serverit (RSA-OAEP/SHA-256)
  - Nënshkrim i mesazheve me çelësin privat të klientit (RSA-PSS/SHA-256)
  - Verifikimi i nënshkrimit dhe integritetit të mesazheve të marra
  - Validimi i inputit para dërgimit
  - CLI interaktive me I/O concurrent (dërgim + pritje njëkohësisht)

Protokolli JSON mbi TCP:
  Çdo paketë është një objekt JSON i serializuar si UTF-8, i ndarë me '\n'.

  Llojet e paketave:
    HELLO   – dërguar menjëherë pas lidhjes, përmban username + PEM public key
    MESSAGE – mesazh i enkriptuar + i nënshkruar
    INFO    – mesazh i thjeshtë tekstual nga serveri (pa enkriptim)
    ERROR   – gabim nga serveri
    BYE     – shkëputja e kontrolluar

Shembull HELLO:
  {
    "type": "HELLO",
    "username": "Alice",
    "public_key": "-----BEGIN PUBLIC KEY-----\\n..."
  }

Shembull MESSAGE:
  {
    "type": "MESSAGE",
    "sender": "Alice",
    "recipient": "Bob",          # ose "ALL" për broadcast
    "ciphertext": "<base64>",
    "signature": "<base64>",
    "timestamp": "2025-05-17T14:30:00"
  }

Ekzekutimi:
  python client.py
  python client.py --host 127.0.0.1 --port 9999 --username Alice
"""

from __future__ import annotations

import argparse
import datetime
import json
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Shtresa e sigurisë – importet nga follderi security/
# ---------------------------------------------------------------------------
try:
    from security.rsa import (
        RSAPrivateKey,
        RSAPublicKey,
        ciphertext_from_base64,
        ciphertext_to_base64,
        decrypt_message_to_text,
        deserialize_public_key,
        encrypt_message,
        generate_keypair,
        message_fits_rsa_limit,
        public_key_fingerprint,
        serialize_public_key,
        sign_data,
        signature_from_base64,
        signature_to_base64,
        verify_signature,
        MessageTooLongError,
        RSADecryptionError,
        RSAError,
    )
    from security.validators import validate_message
    from security.hashing import generate_hash
    from security.integrity import verify_integrity

except ImportError as exc:
    sys.exit(
        f"[GABIM] Importi dështoi: {exc}\n"
        "Sigurohu që follderi 'security/' ndodhet në të njëjtin direktori."
    )

# ---------------------------------------------------------------------------
# Konstantet e klientit
# ---------------------------------------------------------------------------
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9999
DEFAULT_USERNAME = "Client"
KEY_SIZE = 2048
BUFFER_SIZE = 65536          # 64 KB – mjafton për një paketë RSA 2048-bit
SOCKET_TIMEOUT = 60.0        # sekonda
RECONNECT_ATTEMPTS = 3
RECONNECT_DELAY = 2.0        # sekonda


# ---------------------------------------------------------------------------
# Formatimi i mesazheve në terminal
# ---------------------------------------------------------------------------
class Color:
    """Kodet ANSI për ngjyra në terminal (funksionojnë në Linux/macOS/Win10+)."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    GREY    = "\033[90m"
    MAGENTA = "\033[95m"


def _ts() -> str:
    """Timestamp i shkurtër për shfaqje."""
    return datetime.datetime.now().strftime("%H:%M:%S")


def print_info(msg: str) -> None:
    print(f"{Color.CYAN}[{_ts()}] ℹ  {msg}{Color.RESET}")


def print_success(msg: str) -> None:
    print(f"{Color.GREEN}[{_ts()}] ✔  {msg}{Color.RESET}")


def print_warning(msg: str) -> None:
    print(f"{Color.YELLOW}[{_ts()}] ⚠  {msg}{Color.RESET}")


def print_error(msg: str) -> None:
    print(f"{Color.RED}[{_ts()}] ✘  {msg}{Color.RESET}")


def print_message(sender: str, plaintext: str, verified: bool) -> None:
    icon = "🔒" if verified else "⚠️ "
    sig_label = (
        f"{Color.GREEN}[firma OK]{Color.RESET}"
        if verified
        else f"{Color.RED}[firma INVALID]{Color.RESET}"
    )
    print(
        f"\n{Color.BOLD}{Color.MAGENTA}{sender}{Color.RESET} "
        f"{Color.GREY}[{_ts()}]{Color.RESET} {sig_label}\n"
        f"  {icon}  {plaintext}\n"
    )


def print_banner(username: str, fingerprint: str) -> None:
    print(f"""
{Color.CYAN}{'='*60}
  Encrypted Messaging Client  –  Nënshkrimet dhe Çelësat
{'='*60}{Color.RESET}
  Përdoruesi : {Color.BOLD}{username}{Color.RESET}
  Çelësi     : {Color.GREY}{fingerprint}{Color.RESET}
  Enkriptimi : RSA-OAEP / SHA-256  ({KEY_SIZE}-bit)
  Firma      : RSA-PSS  / SHA-256
{Color.CYAN}{'='*60}{Color.RESET}
  Komandat:
    /help          – ndihma
    /whoami        – shfaq çelësin tënd publik
    /quit          – dalje
    /to <user> msg – mesazh privat (nëse serveri e mbështet)
{Color.CYAN}{'='*60}{Color.RESET}
""")


# ---------------------------------------------------------------------------
# Ndërtimi dhe analiza e paketave JSON
# ---------------------------------------------------------------------------
def _now_iso() -> str:
    return datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"


def build_hello_packet(username: str, public_key: RSAPublicKey) -> bytes:
    """Ndërton paketën HELLO me çelësin publik PEM."""
    pem = serialize_public_key(public_key).decode("ascii")
    packet = {
        "type": "HELLO",
        "username": username,
        "public_key": pem,
        "timestamp": _now_iso(),
    }
    return (json.dumps(packet) + "\n").encode("utf-8")


def build_message_packet(
    sender: str,
    plaintext: str,
    recipient_public_key: RSAPublicKey,
    own_private_key: RSAPrivateKey,
    recipient: str = "ALL",
) -> bytes:
    """
    Ndërton paketën MESSAGE:
      1. Enkrripton tekstin e qartë me çelësin publik të marrësit.
      2. Nënshkruan tekstin e qartë me çelësin privat të dërguesit.
      3. Llogarit hash integritetin e tekstit të qartë.
    """
    ciphertext_bytes = encrypt_message(plaintext, recipient_public_key)
    signature_bytes  = sign_data(plaintext, own_private_key)
    integrity_hash   = generate_hash(plaintext)

    packet = {
        "type":      "MESSAGE",
        "sender":    sender,
        "recipient": recipient,
        "ciphertext":  ciphertext_to_base64(ciphertext_bytes),
        "signature":   signature_to_base64(signature_bytes),
        "integrity":   integrity_hash,
        "timestamp":   _now_iso(),
    }
    return (json.dumps(packet) + "\n").encode("utf-8")


def build_bye_packet(username: str) -> bytes:
    packet = {"type": "BYE", "username": username, "timestamp": _now_iso()}
    return (json.dumps(packet) + "\n").encode("utf-8")


def parse_packet(raw: str) -> Optional[dict]:
    """
    Analizon një rresht JSON.  Kthen None nëse formati është i gabuar.
    """
    try:
        data = json.loads(raw.strip())
        if not isinstance(data, dict) or "type" not in data:
            return None
        return data
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# Klasa kryesore e klientit
# ---------------------------------------------------------------------------
class EncryptedClient:
    """
    Klienti i mesazheve të enkriptuara.

    Atributet publike:
        username        – emri i përdoruesit
        private_key     – çelësi privat RSA i klientit
        public_key      – çelësi publik RSA i klientit
        server_pub_key  – çelësi publik RSA i serverit (pas handshake-ut)
    """

    def __init__(self, host: str, port: int, username: str) -> None:
        self.host     = host
        self.port     = port
        self.username = username

        # Gjenerimi i çiftit të çelësave
        print_info(f"Duke gjeneruar çiftin e çelësave RSA {KEY_SIZE}-bit...")
        self.private_key, self.public_key = generate_keypair(key_size=KEY_SIZE)
        self.fingerprint = public_key_fingerprint(self.public_key)
        print_success("Çelësat u gjeneruan.")

        self.server_pub_key: Optional[RSAPublicKey] = None
        self._sock: Optional[socket.socket]         = None
        self._connected  = False
        self._running    = False
        self._recv_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()   # për shkrim të sigurt në socket

    # ------------------------------------------------------------------
    # Lidhja dhe handshake-u
    # ------------------------------------------------------------------
    def connect(self) -> bool:
        """
        Lidhet me serverin dhe kryen handshake-un RSA.
        Kthen True nëse lidhja u krye me sukses.
        """
        for attempt in range(1, RECONNECT_ATTEMPTS + 1):
            try:
                print_info(f"Duke u lidhur me {self.host}:{self.port} (tentativa {attempt}/{RECONNECT_ATTEMPTS})...")
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(SOCKET_TIMEOUT)
                sock.connect((self.host, self.port))
                self._sock = sock
                self._connected = True
                print_success(f"Lidhja me serverin u krye.")
                break
            except (ConnectionRefusedError, OSError) as err:
                print_error(f"Lidhja dështoi: {err}")
                if attempt < RECONNECT_ATTEMPTS:
                    print_info(f"Duke pritur {RECONNECT_DELAY}s para se të provojë sërish...")
                    time.sleep(RECONNECT_DELAY)
                else:
                    return False

        # Dërgojmë HELLO me çelësin tonë publik
        try:
            self._send_raw(build_hello_packet(self.username, self.public_key))
            print_info("HELLO u dërgua. Duke pritur çelësin publik të serverit...")
        except OSError as err:
            print_error(f"Dërgimi i HELLO dështoi: {err}")
            return False

        # Marrim HELLO nga serveri (çelësi i tij publik)
        try:
            response_line = self._recv_line()
            if not response_line:
                print_error("Serveri nuk dërgoi përgjigje HELLO.")
                return False

            packet = parse_packet(response_line)
            if not packet:
                print_error("Paketë e pavlefshme nga serveri gjatë handshake-ut.")
                return False

            if packet.get("type") == "HELLO":
                pem = packet.get("public_key", "")
                if not pem:
                    print_error("Serveri nuk dërgoi çelësin publik.")
                    return False
                self.server_pub_key = deserialize_public_key(pem)
                server_fp = public_key_fingerprint(self.server_pub_key)
                print_success(f"Çelësi publik i serverit u mor.")
                print_info(f"Gjurma e serverit: {server_fp}")

            elif packet.get("type") == "ERROR":
                print_error(f"Serveri refuzoi lidhjen: {packet.get('message', '')}")
                return False
            else:
                print_warning(f"Lloji i paketës i papritur gjatë handshake-ut: {packet.get('type')}")
                return False

        except (OSError, UnicodeDecodeError) as err:
            print_error(f"Gabim gjatë leximit të handshake-ut: {err}")
            return False

        return True

    # ------------------------------------------------------------------
    # Dërgimi i mesazheve
    # ------------------------------------------------------------------
    def send_message(self, plaintext: str, recipient: str = "ALL") -> bool:
        """
        Valido → enkripto → nënshkruaj → dërgo.
        Kthen True nëse dërgimi u krye me sukses.
        """
        if not self._connected or self._sock is None:
            print_error("Nuk je i lidhur me serverin.")
            return False

        if self.server_pub_key is None:
            print_error("Çelësi publik i serverit mungon. Handshake-u nuk u krye.")
            return False

        # 1. Validimi i inputit
        if not validate_message(plaintext):
            print_warning(
                "Mesazhi nuk kaloi validimin.\n"
                "  • Duhet të jetë tekst jo-bosh\n"
                "  • Gjatësia maksimale: 1024 karaktere"
            )
            return False

        # 2. Kontrolli i limitit RSA-OAEP
        if not message_fits_rsa_limit(plaintext, self.server_pub_key):
            max_b = self.server_pub_key.max_oaep_message_length()
            print_warning(
                f"Mesazhi është shumë i gjatë për enkriptim RSA-OAEP ({max_b} bytes max).\n"
                "Ndaje mesazhin në pjesë më të vogla."
            )
            return False

        # 3. Ndërtimi dhe dërgimi i paketës
        try:
            packet = build_message_packet(
                sender=self.username,
                plaintext=plaintext,
                recipient_public_key=self.server_pub_key,
                own_private_key=self.private_key,
                recipient=recipient,
            )
            self._send_raw(packet)
            return True

        except MessageTooLongError as err:
            print_error(f"Gabim enkriptimi (mesazh shumë i gjatë): {err}")
            return False
        except RSAError as err:
            print_error(f"Gabim RSA gjatë dërgimit: {err}")
            return False
        except OSError as err:
            print_error(f"Gabim rrjeti gjatë dërgimit: {err}")
            self._connected = False
            return False

    # ------------------------------------------------------------------
    # Marrja dhe procesimi i mesazheve
    # ------------------------------------------------------------------
    def _handle_incoming_packet(self, packet: dict) -> None:
        """Proceson çdo paketë të marrë nga serveri."""
        ptype = packet.get("type", "")

        if ptype == "MESSAGE":
            self._process_message_packet(packet)

        elif ptype == "INFO":
            text = packet.get("message", "")
            print_info(f"[SERVER] {text}")

        elif ptype == "ERROR":
            print_error(f"[SERVER ERROR] {packet.get('message', 'gabim i panjohur')}")

        elif ptype == "BYE":
            who = packet.get("username", "dikush")
            print_info(f"{who} u shkëput nga chat-i.")

        else:
            print_warning(f"Paketë me lloj të panjohur: {ptype!r}")

    def _process_message_packet(self, packet: dict) -> None:
        """
        Proceson një paketë MESSAGE:
          1. Dekriptoi ciphertextin me çelësin privat tonë.
          2. Verifiko nënshkrimin me çelësin publik të dërguesit.
          3. Verifiko integritetin me hash-in e bashkëngjitur.
        """
        sender    = packet.get("sender", "i panjohur")
        ct_b64    = packet.get("ciphertext", "")
        sig_b64   = packet.get("signature", "")
        integrity = packet.get("integrity", "")

        # --- Dekriptimi ---
        try:
            ciphertext = ciphertext_from_base64(ct_b64)
            plaintext  = decrypt_message_to_text(ciphertext, self.private_key)
        except RSADecryptionError as err:
            print_error(f"Mesazhi nga '{sender}' nuk u dekriptua: {err}")
            return
        except Exception as err:
            print_error(f"Gabim i papritur gjatë dekriptimit: {err}")
            return

        # --- Verifikimi i integritetit ---
        if integrity:
            if not verify_integrity(integrity, plaintext):
                print_warning(f"INTEGRITET I DËMTUAR: mesazhi nga '{sender}' mund të jetë ndryshuar!")

        # --- Verifikimi i nënshkrimit ---
        #
        # Klienti ruan çelësin publik vetëm të serverit.
        # Nëse dërgimi vjen nga serveri (relay), verifikojmë me çelësin e serverit.
        # Nëse arkitektura mbështet peer-to-peer, duhet cache-u i çelësave publikë.
        # Këtu implementojmë verifikimin e disponueshëm:
        signature_verified = False
        if sig_b64 and self.server_pub_key is not None:
            try:
                signature_bytes    = signature_from_base64(sig_b64)
                signature_verified = verify_signature(plaintext, signature_bytes, self.server_pub_key)
            except Exception:
                signature_verified = False

        print_message(sender, plaintext, signature_verified)

    # ------------------------------------------------------------------
    # Thread-i i marrjes
    # ------------------------------------------------------------------
    def _receive_loop(self) -> None:
        """
        Ekzekuton në thread të veçantë.
        Lexon rreshta JSON nga serveri dhe i proceson.
        """
        buffer = ""
        while self._running and self._connected:
            try:
                chunk = self._sock.recv(BUFFER_SIZE).decode("utf-8")
                if not chunk:
                    print_info("Serveri e mbyll lidhjen.")
                    self._connected = False
                    self._running   = False
                    break
                buffer += chunk
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    packet = parse_packet(line)
                    if packet:
                        self._handle_incoming_packet(packet)
                    else:
                        print_warning(f"Paketë e paanalizueshme: {line[:80]}")
            except socket.timeout:
                continue   # timeout normal, vazhdo loop-in
            except (OSError, UnicodeDecodeError) as err:
                if self._running:
                    print_error(f"Gabim marrjeje: {err}")
                self._connected = False
                self._running   = False
                break

    # ------------------------------------------------------------------
    # Laku kryesor CLI
    # ------------------------------------------------------------------
    def run(self) -> None:
        """
        Nis thread-in e marrjes dhe hap CLI-në interaktive.
        """
        if not self._connected:
            print_error("Nuk ka lidhje aktive. Thirr connect() së pari.")
            return

        self._running = True
        self._recv_thread = threading.Thread(
            target=self._receive_loop,
            daemon=True,
            name="recv-thread",
        )
        self._recv_thread.start()

        print_banner(self.username, self.fingerprint)
        print_info("Shkruaj mesazhin dhe shtyp Enter për ta dërguar.")
        print_info("Shkruaj /quit ose /q për të dalë.\n")

        try:
            while self._running:
                try:
                    user_input = input(
                        f"{Color.BOLD}{Color.GREEN}{self.username}{Color.RESET} > "
                    ).strip()
                except (EOFError, KeyboardInterrupt):
                    break

                if not user_input:
                    continue

                # ---- Komandat e brendshme ----
                if user_input.lower() in ("/quit", "/q", "/exit"):
                    break

                if user_input.lower() in ("/help", "/h"):
                    self._print_help()
                    continue

                if user_input.lower() == "/whoami":
                    self._print_whoami()
                    continue

                if user_input.lower().startswith("/to "):
                    self._handle_private_message(user_input)
                    continue

                if user_input.startswith("/"):
                    print_warning(f"Komandë e panjohur: {user_input}. Shkruaj /help.")
                    continue

                # ---- Dërgim mesazhi broadcast ----
                ok = self.send_message(user_input)
                if ok:
                    # Echo lokal i mesazhit tënd
                    print(
                        f"  {Color.GREY}[dërguar {_ts()}] "
                        f"🔒 [enkriptuar + nënshkruar]{Color.RESET}"
                    )

        finally:
            self._shutdown()

    def _handle_private_message(self, user_input: str) -> None:
        """
        Trajton komandën  /to <recipient> <mesazhi>
        Shembull: /to Bob Përshëndetje Bob!
        """
        parts = user_input[4:].split(" ", 1)
        if len(parts) < 2 or not parts[1].strip():
            print_warning("Sintaksa: /to <recipient> <mesazhi>")
            return
        recipient, message = parts[0], parts[1].strip()
        ok = self.send_message(message, recipient=recipient)
        if ok:
            print(
                f"  {Color.GREY}[mesazh privat dërguar te '{recipient}' – {_ts()}]"
                f" 🔒 [enkriptuar + nënshkruar]{Color.RESET}"
            )

    def _print_help(self) -> None:
        print(f"""
{Color.CYAN}── Ndihma ──────────────────────────────────────{Color.RESET}
  <tekst>            – dërgon mesazh broadcast
  /to <user> <msg>   – dërgon mesazh privat
  /whoami            – shfaq çelësin tënd publik dhe gjurmën
  /help              – kjo listë
  /quit              – dalje nga klienti
{Color.CYAN}────────────────────────────────────────────────{Color.RESET}
""")

    def _print_whoami(self) -> None:
        pem = serialize_public_key(self.public_key).decode("ascii")
        print(f"""
{Color.CYAN}── Identiteti yt ───────────────────────────────{Color.RESET}
  Emri     : {self.username}
  Gjurma   : {self.fingerprint}
  Çelësi publik:
{Color.GREY}{pem}{Color.RESET}
{Color.CYAN}────────────────────────────────────────────────{Color.RESET}
""")

    # ------------------------------------------------------------------
    # Metodat ndihmëse private
    # ------------------------------------------------------------------
    def _send_raw(self, data: bytes) -> None:
        """Dërgon bytes me bllok për shkrim thread-safe."""
        with self._lock:
            total_sent = 0
            while total_sent < len(data):
                sent = self._sock.send(data[total_sent:])
                if sent == 0:
                    raise OSError("Lidhja me serverin u pre gjatë dërgimit.")
                total_sent += sent

    def _recv_line(self) -> Optional[str]:
        """Lexon një rresht të vetëm nga socket-i (bllokues)."""
        buf = b""
        while b"\n" not in buf:
            chunk = self._sock.recv(BUFFER_SIZE)
            if not chunk:
                return None
            buf += chunk
        line, _ = buf.split(b"\n", 1)
        return line.decode("utf-8")

    def _shutdown(self) -> None:
        """Mbyll lidhjen me pastrim të plotë."""
        self._running   = False
        self._connected = False
        if self._sock:
            try:
                self._send_raw(build_bye_packet(self.username))
            except OSError:
                pass
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._sock.close()
            self._sock = None
        print_info("Lidhja u mbyll. Mirupafshim!")


# ---------------------------------------------------------------------------
# Analiza e argumenteve CLI
# ---------------------------------------------------------------------------
def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="client.py",
        description="Encrypted Messaging Client – Nënshkrimet dhe Çelësat",
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"Adresa IP e serverit (default: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Porti i serverit (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--username",
        default=DEFAULT_USERNAME,
        help=f"Emri i përdoruesit (default: {DEFAULT_USERNAME})",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Hyrja kryesore
# ---------------------------------------------------------------------------
def main() -> int:
    args = _parse_args()

    username = args.username.strip()
    if not username or len(username) > 32:
        print_error("Emri i përdoruesit duhet të jetë 1–32 karaktere.")
        return 1

    client = EncryptedClient(
        host=args.host,
        port=args.port,
        username=username,
    )

    connected = client.connect()
    if not connected:
        print_error(
            f"Nuk u arrit të lidhet me {args.host}:{args.port}.\n"
            "Kontrollo nëse serveri është duke ekzekutuar dhe provo sërish."
        )
        return 1

    client.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
