"""
server.py – Encrypted Messaging Server
=======================================
Anëtari 1: Server Application

Përgjegjësitë:
  - Dëgjimi i lidhjeve TCP nga klientët (multi-client)
  - RSA key-exchange (handshake HELLO) me çdo klient
  - Autentikimi dhe menaxhimi i sesioneve
  - Dekriptimi i mesazheve hyrëse (me çelësin privat të serverit)
  - Ri-enkriptimi dhe ridërgimi te marrësi (me çelësin publik të marrësit)
  - Ri-nënshkrimi i mesazheve të ridetyruara me çelësin privat të serverit
  - Rutimi: broadcast (ALL) dhe mesazhe private (/to <user>)
  - Logimi i plotë i ngjarjeve dhe i gabimeve

Protokolli JSON mbi TCP:
  Çdo paketë është një objekt JSON i serializuar si UTF-8, i ndarë me '\\n'.

  Llojet e paketave (dërgim / marrje):
    HELLO   – shkëmbim çelësash pas lidhjes
    MESSAGE – mesazh i enkriptuar + i nënshkruar
    INFO    – njoftim tekstual nga serveri te klienti
    ERROR   – njoftim gabimi nga serveri te klienti
    BYE     – shkëputja e kontrolluar

Ekzekutimi:
  python server.py
  python server.py --host 0.0.0.0 --port 9999 --max-clients 50
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import socket
import sys
import threading
import time
from typing import Dict, Optional, Tuple

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
# Konstantet e serverit
# ---------------------------------------------------------------------------
DEFAULT_HOST        = "0.0.0.0"
DEFAULT_PORT        = 9999
DEFAULT_MAX_CLIENTS = 50
KEY_SIZE            = 2048
BUFFER_SIZE         = 65536   # 64 KB
SOCKET_TIMEOUT      = 120.0   # sekonda — koha maksimale e joaktivitetit
MAX_USERNAME_LEN    = 32
HEARTBEAT_INTERVAL  = 30.0    # sekonda

# ---------------------------------------------------------------------------
# Konfigurimi i logjimit
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("server.log", encoding="utf-8"),
    ],
)
log = logging.getLogger("server")


# ---------------------------------------------------------------------------
# Ndërtimi dhe analiza e paketave JSON
# ---------------------------------------------------------------------------
def _now_iso() -> str:
    return datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"


def build_hello_packet(public_key: RSAPublicKey) -> bytes:
    """Paketë HELLO e serverit – dërgon çelësin publik PEM."""
    pem = serialize_public_key(public_key).decode("ascii")
    packet = {
        "type":       "HELLO",
        "username":   "__SERVER__",
        "public_key": pem,
        "timestamp":  _now_iso(),
    }
    return (json.dumps(packet) + "\n").encode("utf-8")


def build_info_packet(message: str) -> bytes:
    """Paketë INFO – njoftim tekstual i thjeshtë."""
    packet = {"type": "INFO", "message": message, "timestamp": _now_iso()}
    return (json.dumps(packet) + "\n").encode("utf-8")


def build_error_packet(message: str) -> bytes:
    """Paketë ERROR – lajmërim gabimi."""
    packet = {"type": "ERROR", "message": message, "timestamp": _now_iso()}
    return (json.dumps(packet) + "\n").encode("utf-8")


def build_bye_packet(username: str) -> bytes:
    """Paketë BYE – lajmërim shkëputjeje."""
    packet = {"type": "BYE", "username": username, "timestamp": _now_iso()}
    return (json.dumps(packet) + "\n").encode("utf-8")


def build_message_packet(
    sender: str,
    plaintext: str,
    recipient_public_key: RSAPublicKey,
    server_private_key: RSAPrivateKey,
    recipient: str = "ALL",
) -> bytes:
    """
    Ndërton paketën MESSAGE për ri-dërgim:
      1. Enkrripton me çelësin publik të marrësit.
      2. Ri-nënshkruan me çelësin privat të serverit.
      3. Bashkëngjet hash-in e integritetit.
    """
    ciphertext_bytes = encrypt_message(plaintext, recipient_public_key)
    signature_bytes  = sign_data(plaintext, server_private_key)
    integrity_hash   = generate_hash(plaintext)

    packet = {
        "type":       "MESSAGE",
        "sender":     sender,
        "recipient":  recipient,
        "ciphertext": ciphertext_to_base64(ciphertext_bytes),
        "signature":  signature_to_base64(signature_bytes),
        "integrity":  integrity_hash,
        "timestamp":  _now_iso(),
    }
    return (json.dumps(packet) + "\n").encode("utf-8")


def parse_packet(raw: str) -> Optional[dict]:
    """Analizon një rresht JSON. Kthen None nëse formati është i gabuar."""
    try:
        data = json.loads(raw.strip())
        if not isinstance(data, dict) or "type" not in data:
            return None
        return data
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# Sesioni i klientit – një thread për klient
# ---------------------------------------------------------------------------
class ClientSession:
    """
    Përfaqëson një klient të lidhur me serverin.

    Atributet:
        username    – emri i verifikuar i klientit (pas HELLO)
        address     – (ip, port) i klientit
        public_key  – çelësi publik RSA i klientit (pas HELLO)
        connected   – a është aktive lidhja
    """

    def __init__(
        self,
        conn: socket.socket,
        address: Tuple[str, int],
        server: "EncryptedServer",
    ) -> None:
        self.conn      = conn
        self.address   = address
        self.server    = server
        self.username: Optional[str]    = None
        self.public_key: Optional[RSAPublicKey] = None
        self.connected = True
        self._lock     = threading.Lock()
        self._joined_at = time.time()

    # ------------------------------------------------------------------
    # Dërgimi thread-safe
    # ------------------------------------------------------------------
    def send_raw(self, data: bytes) -> bool:
        """Dërgon bytes në socket. Kthen False nëse lidhja është e dëmtuar."""
        with self._lock:
            try:
                total = 0
                while total < len(data):
                    sent = self.conn.send(data[total:])
                    if sent == 0:
                        self.connected = False
                        return False
                    total += sent
                return True
            except OSError:
                self.connected = False
                return False

    def send_info(self, message: str) -> None:
        self.send_raw(build_info_packet(message))

    def send_error(self, message: str) -> None:
        self.send_raw(build_error_packet(message))

    # ------------------------------------------------------------------
    # Leximi i një rreshti (handshake)
    # ------------------------------------------------------------------
    def recv_line(self) -> Optional[str]:
        """Lexon një rresht të vetëm nga socket-i (bllokues, për handshake)."""
        buf = b""
        try:
            while b"\n" not in buf:
                chunk = self.conn.recv(BUFFER_SIZE)
                if not chunk:
                    return None
                buf += chunk
            line, _ = buf.split(b"\n", 1)
            return line.decode("utf-8")
        except (OSError, UnicodeDecodeError):
            return None

    # ------------------------------------------------------------------
    # Handshake-u RSA
    # ------------------------------------------------------------------
    def do_handshake(self) -> bool:
        """
        Kryen shkëmbimin e çelësave:
          1. Pret HELLO nga klienti (username + public_key).
          2. Valido username dhe çelësin.
          3. Regjistron klientin në server (kontrollon konflikte username).
          4. Dërgon HELLO të serverit me çelësin publik të tij.
        Kthen True nëse handshake-u u krye me sukses.
        """
        log.info(f"[{self.address}] Duke kryer handshake...")

        raw = self.recv_line()
        if not raw:
            log.warning(f"[{self.address}] Asnjë të dhënë gjatë handshake-ut.")
            return False

        packet = parse_packet(raw)
        if not packet or packet.get("type") != "HELLO":
            log.warning(f"[{self.address}] Paketë HELLO e gabuar.")
            self.send_error("Pritet paketa HELLO si hap i parë.")
            return False

        # Validimi i username-it
        username = str(packet.get("username", "")).strip()
        if not username or len(username) > MAX_USERNAME_LEN:
            self.send_error(
                f"Username duhet të jetë 1–{MAX_USERNAME_LEN} karaktere."
            )
            return False

        # Validimi dhe deserializimi i çelësit publik
        pem = packet.get("public_key", "")
        if not pem:
            self.send_error("Çelësi publik mungon në HELLO.")
            return False
        try:
            client_pub_key = deserialize_public_key(pem)
        except Exception as err:
            log.warning(f"[{self.address}] Çelës publik i pavlefshëm: {err}")
            self.send_error("Çelësi publik RSA është i pavlefshëm ose i prishur.")
            return False

        # Kontrolli i konfliktit të username-it
        if not self.server.register_client(username, self):
            self.send_error(f"Emri '{username}' është tashmë në përdorim.")
            log.warning(
                f"[{self.address}] Username '{username}' refuzuar – tashmë ekziston."
            )
            return False

        self.username   = username
        self.public_key = client_pub_key
        fingerprint     = public_key_fingerprint(client_pub_key)
        log.info(
            f"[{self.address}] Klienti '{username}' u regjistrua. "
            f"Gjurma: {fingerprint}"
        )

        # Dërgojmë HELLO të serverit
        ok = self.send_raw(build_hello_packet(self.server.public_key))
        if not ok:
            log.warning(f"[{self.address}] Dërgimi i HELLO dështoi.")
            return False

        log.info(f"[{self.address}] Handshake me '{username}' u krye me sukses.")
        return True

    # ------------------------------------------------------------------
    # Laku kryesor i leximit
    # ------------------------------------------------------------------
    def run(self) -> None:
        """
        Ekzekutohet në thread të veçantë.
        Lexon paketa JSON dhe i kalon serverit për procesim.
        """
        buffer = ""
        try:
            while self.connected:
                try:
                    chunk = self.conn.recv(BUFFER_SIZE).decode("utf-8")
                    if not chunk:
                        log.info(
                            f"[{self.address}] Klienti '{self.username}' "
                            "e mbyll lidhjen (EOF)."
                        )
                        break
                    buffer += chunk
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        line = line.strip()
                        if not line:
                            continue
                        packet = parse_packet(line)
                        if packet:
                            self.server.handle_packet(self, packet)
                        else:
                            log.warning(
                                f"[{self.address}] Paketë e paanalizueshme: "
                                f"{line[:120]}"
                            )
                            self.send_error("Formati i paketës JSON është i gabuar.")

                except socket.timeout:
                    # Timeout normal — vazhdo loop-in
                    continue
                except (OSError, UnicodeDecodeError) as err:
                    log.error(
                        f"[{self.address}] Gabim leximi nga '{self.username}': {err}"
                    )
                    break
        finally:
            self._cleanup()

    # ------------------------------------------------------------------
    # Pastrimi i sesionit
    # ------------------------------------------------------------------
    def _cleanup(self) -> None:
        self.connected = False
        self.server.unregister_client(self)
        try:
            self.conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.conn.close()
        except OSError:
            pass
        log.info(
            f"[{self.address}] Sesioni i '{self.username}' u mbyll."
        )


# ---------------------------------------------------------------------------
# Serveri kryesor
# ---------------------------------------------------------------------------
class EncryptedServer:
    """
    Server i mesazheve të enkriptuara – multi-client, thread per klient.

    Funksionet kryesore:
      • Dëgjon lidhje TCP në (host, port).
      • Gjeneron çiftin e çelësave RSA të serverit.
      • Kryen handshake RSA me çdo klient.
      • Rut mesazhe: broadcast dhe private.
      • Valido dhe verifiko integritetin e çdo mesazhi.
    """

    def __init__(self, host: str, port: int, max_clients: int) -> None:
        self.host        = host
        self.port        = port
        self.max_clients = max_clients

        # Gjenerimi i çiftit të çelësave të serverit
        log.info(f"Duke gjeneruar çiftin e çelësave RSA {KEY_SIZE}-bit...")
        self.private_key, self.public_key = generate_keypair(key_size=KEY_SIZE)
        self.fingerprint = public_key_fingerprint(self.public_key)
        log.info(f"Çelësat u gjeneruan. Gjurma: {self.fingerprint}")

        # Regjistri i klientëve  { username -> ClientSession }
        self._clients: Dict[str, ClientSession] = {}
        self._clients_lock = threading.Lock()

        self._server_sock: Optional[socket.socket] = None
        self._running = False

    # ------------------------------------------------------------------
    # Menaxhimi i klientëve
    # ------------------------------------------------------------------
    def register_client(self, username: str, session: ClientSession) -> bool:
        """
        Regjistron klientin. Kthen False nëse username ekziston tashmë.
        Thread-safe.
        """
        with self._clients_lock:
            if username in self._clients:
                return False
            if len(self._clients) >= self.max_clients:
                log.warning(
                    f"Klienti '{username}' refuzuar – kapaciteti maksimal "
                    f"({self.max_clients}) u arrit."
                )
                return False
            self._clients[username] = session
            return True

    def unregister_client(self, session: ClientSession) -> None:
        """Heq klientin nga regjistri dhe njofton të tjerët. Thread-safe."""
        username = session.username
        if not username:
            return
        with self._clients_lock:
            self._clients.pop(username, None)

        log.info(f"Klienti '{username}' u çregjistrua. Aktualë: {self.client_count()}")
        self._broadcast_info(
            f"{username} u shkëput nga biseda.",
            exclude=username,
        )
        # Dërgojmë paketë BYE te të gjithë
        self._broadcast_raw(build_bye_packet(username), exclude=username)

    def client_count(self) -> int:
        with self._clients_lock:
            return len(self._clients)

    def _get_client(self, username: str) -> Optional[ClientSession]:
        with self._clients_lock:
            return self._clients.get(username)

    def _all_sessions(self) -> list[ClientSession]:
        with self._clients_lock:
            return list(self._clients.values())

    # ------------------------------------------------------------------
    # Proceimi i paketave
    # ------------------------------------------------------------------
    def handle_packet(self, session: ClientSession, packet: dict) -> None:
        """
        Dispatcho-n paketën sipas llojit.
        Thirrët nga thread-i i çdo sesioni.
        """
        ptype = packet.get("type", "")

        if ptype == "MESSAGE":
            self._handle_message(session, packet)
        elif ptype == "BYE":
            log.info(f"Klienti '{session.username}' dërgoi BYE.")
            session.connected = False
        elif ptype == "HELLO":
            # HELLO i dytë – i papritur pas handshake-ut
            log.warning(
                f"[{session.address}] HELLO i papritur pas handshake-ut – injorohet."
            )
            session.send_error("HELLO pritet vetëm gjatë lidhjes fillestare.")
        else:
            log.warning(
                f"[{session.address}] Lloji i paketës i panjohur: {ptype!r}"
            )
            session.send_error(f"Lloji i paketës '{ptype}' nuk njihet.")

    def _handle_message(self, session: ClientSession, packet: dict) -> None:
        """
        Proceson një paketë MESSAGE:
          1. Dekrripto me çelësin privat të serverit.
          2. Valido tekstin e qartë (validate_message).
          3. Verifiko integritetin (hash).
          4. Verifiko nënshkrimin e dërguesit.
          5. Ruto te marrësi/marrësit (ri-enkriptim për secilin).
        """
        sender    = session.username
        ct_b64    = packet.get("ciphertext", "")
        sig_b64   = packet.get("signature",  "")
        integrity = packet.get("integrity",  "")
        recipient = packet.get("recipient", "ALL").strip()

        # ── 1. Dekriptimi ──────────────────────────────────────────────
        try:
            ciphertext = ciphertext_from_base64(ct_b64)
            plaintext  = decrypt_message_to_text(ciphertext, self.private_key)
        except RSADecryptionError as err:
            log.error(f"Dekriptimi i mesazhit nga '{sender}' dështoi: {err}")
            session.send_error("Mesazhi nuk u dekriptua. Kontrollo enkriptimin.")
            return
        except Exception as err:
            log.error(f"Gabim i papritur gjatë dekriptimit nga '{sender}': {err}")
            session.send_error("Gabim i brendshëm gjatë dekriptimit.")
            return

        # ── 2. Validimi i mesazhit ─────────────────────────────────────
        if not validate_message(plaintext):
            log.warning(f"Mesazh i pavlefshëm nga '{sender}': validimi dështoi.")
            session.send_error(
                "Mesazhi nuk është i vlefshëm "
                "(bosh, ose tejkalon 1024 karaktere)."
            )
            return

        # ── 3. Verifikimi i integritetit ───────────────────────────────
        if integrity:
            if not verify_integrity(integrity, plaintext):
                log.warning(
                    f"INTEGRITET I DËMTUAR nga '{sender}': "
                    "hash-i nuk përputhet me tekstin."
                )
                session.send_error(
                    "Mesazhi i marrë ka integritet të dëmtuar dhe u refuzua."
                )
                return
        else:
            log.debug(f"Mesazhi nga '{sender}' nuk ka hash integriteti (opsional).")

        # ── 4. Verifikimi i nënshkrimit të dërguesit ──────────────────
        signature_ok = False
        if sig_b64 and session.public_key is not None:
            try:
                sig_bytes    = signature_from_base64(sig_b64)
                signature_ok = verify_signature(
                    plaintext, sig_bytes, session.public_key
                )
            except Exception as sig_err:
                log.warning(
                    f"Gabim gjatë verifikimit të nënshkrimit nga '{sender}': {sig_err}"
                )

        if not signature_ok:
            log.warning(f"Nënshkrimi i mesazhit nga '{sender}' është INVALID.")
            # E pranojmë mesazhin por e shënojmë — klienti do shohë ikonën ⚠️
            # Ndryshoje në `return` nëse doni politikë strikte.

        log.info(
            f"MSG  '{sender}' → '{recipient}' | "
            f"gjatësia={len(plaintext)}B | "
            f"nënshkrimi={'OK' if signature_ok else 'INVALID'}"
        )

        # ── 5. Rutimi ──────────────────────────────────────────────────
        if recipient.upper() == "ALL":
            self._route_broadcast(sender, plaintext)
        else:
            self._route_private(sender, plaintext, recipient, session)

    # ------------------------------------------------------------------
    # Rutimi i mesazheve
    # ------------------------------------------------------------------
    def _route_broadcast(self, sender: str, plaintext: str) -> None:
        """
        Dërgon mesazhin te të gjithë klientët përveç dërguesit.
        Çdo marrës merr mesazhin e enkriptuar me çelësin e tij publik.
        """
        targets = [
            s for s in self._all_sessions()
            if s.username != sender and s.connected and s.public_key is not None
        ]
        if not targets:
            return

        for target in targets:
            self._deliver(sender, plaintext, target, recipient_label="ALL")

    def _route_private(
        self,
        sender: str,
        plaintext: str,
        recipient_username: str,
        sender_session: ClientSession,
    ) -> None:
        """
        Dërgon mesazhin vetëm te marrësi specifik.
        """
        target = self._get_client(recipient_username)
        if target is None:
            log.warning(
                f"Mesazh privat nga '{sender}' te '{recipient_username}' "
                "dështoi: marrësi nuk u gjet."
            )
            sender_session.send_error(
                f"Përdoruesi '{recipient_username}' nuk është i lidhur."
            )
            return
        if not target.connected or target.public_key is None:
            sender_session.send_error(
                f"Çelësi publik i '{recipient_username}' nuk është i disponueshëm."
            )
            return

        self._deliver(sender, plaintext, target, recipient_label=recipient_username)

    def _deliver(
        self,
        sender: str,
        plaintext: str,
        target: ClientSession,
        recipient_label: str,
    ) -> None:
        """
        Enkrripton dhe dërgon mesazhin te target-i.
        Nëse mesazhi është shumë i gjatë për çelësin e marrësit, e sinjalizon.
        """
        try:
            if not message_fits_rsa_limit(plaintext, target.public_key):
                log.warning(
                    f"Mesazhi nga '{sender}' është shumë i gjatë për "
                    f"çelësin e '{target.username}' – u kapërcye."
                )
                return

            packet = build_message_packet(
                sender=sender,
                plaintext=plaintext,
                recipient_public_key=target.public_key,
                server_private_key=self.private_key,
                recipient=recipient_label,
            )
            ok = target.send_raw(packet)
            if not ok:
                log.warning(
                    f"Dërgimi te '{target.username}' dështoi (lidhja e dëmtuar)."
                )

        except MessageTooLongError as err:
            log.error(f"Enkriptim dështoi (mesazh shumë i gjatë): {err}")
        except RSAError as err:
            log.error(f"Gabim RSA gjatë dërgimit te '{target.username}': {err}")
        except Exception as err:
            log.error(
                f"Gabim i papritur gjatë dorëzimit te '{target.username}': {err}"
            )

    # ------------------------------------------------------------------
    # Transmetime broadcast nga serveri
    # ------------------------------------------------------------------
    def _broadcast_info(self, message: str, exclude: Optional[str] = None) -> None:
        """Dërgon paketë INFO te të gjithë klientët (me përjashtim opsional)."""
        packet = build_info_packet(message)
        for session in self._all_sessions():
            if exclude and session.username == exclude:
                continue
            session.send_raw(packet)

    def _broadcast_raw(self, data: bytes, exclude: Optional[str] = None) -> None:
        """Dërgon bytes të papërpunuara te të gjithë klientët."""
        for session in self._all_sessions():
            if exclude and session.username == exclude:
                continue
            session.send_raw(data)

    # ------------------------------------------------------------------
    # Laku kryesor i serverit
    # ------------------------------------------------------------------
    def start(self) -> None:
        """
        Nis dëgjimin e lidhjeve dhe procesin e pranimit.
        Bllokohet deri sa të thirret stop() ose të ndodhë Ctrl+C.
        """
        try:
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.bind((self.host, self.port))
            self._server_sock.listen(self.max_clients)
            self._running = True
            log.info(
                f"Serveri dëgjon në {self.host}:{self.port} "
                f"(max {self.max_clients} klientë)"
            )
            log.info(f"Gjurma RSA e serverit: {self.fingerprint}")
            self._print_banner()
        except OSError as err:
            log.critical(f"Serveri nuk u nis: {err}")
            sys.exit(1)

        try:
            while self._running:
                try:
                    self._server_sock.settimeout(1.0)
                    try:
                        conn, addr = self._server_sock.accept()
                    except socket.timeout:
                        continue   # kthehu dhe kontrollo self._running
                except OSError as err:
                    if self._running:
                        log.error(f"Gabim pranimi: {err}")
                    break

                # Kufizim kapaciteti
                if self.client_count() >= self.max_clients:
                    log.warning(
                        f"Lidhja nga {addr} refuzuar – kapaciteti maksimal u arrit."
                    )
                    try:
                        conn.send(
                            build_error_packet(
                                "Serveri është i mbushur. Provo më vonë."
                            )
                        )
                        conn.close()
                    except OSError:
                        pass
                    continue

                conn.settimeout(SOCKET_TIMEOUT)
                session = ClientSession(conn, addr, self)
                log.info(
                    f"Lidhje e re nga {addr}. "
                    f"Klientë aktivë: {self.client_count() + 1}"
                )

                # Thread individual për çdo klient
                t = threading.Thread(
                    target=self._session_entry,
                    args=(session,),
                    daemon=True,
                    name=f"client-{addr[0]}:{addr[1]}",
                )
                t.start()

        except KeyboardInterrupt:
            log.info("Ctrl+C u zbulua. Ndalimi i serverit...")
        finally:
            self.stop()

    def _session_entry(self, session: ClientSession) -> None:
        """
        Pika e hyrjes për çdo thread klienti.
        Kryen handshake-un, pastaj hyn në loop-in e leximit.
        """
        ok = session.do_handshake()
        if not ok:
            session._cleanup()
            return

        # Njofto klientët e tjerë
        self._broadcast_info(
            f"{session.username} u bashkua me bisedën!",
            exclude=session.username,
        )
        session.send_info(
            f"Mirë se erdhe, {session.username}! "
            f"Klientë aktivë: {self.client_count()}"
        )

        session.run()

    # ------------------------------------------------------------------
    # Ndalimi i serverit
    # ------------------------------------------------------------------
    def stop(self) -> None:
        """Mbyll serverin me pastrim të plotë."""
        self._running = False
        log.info("Duke njoftuar klientët për ndalimin e serverit...")
        self._broadcast_info("Serveri po ndalet. Lidhja do të mbyllet.")
        # Presim pak që klientët të marrin njoftimin
        time.sleep(0.5)
        # Mbyllim të gjitha sesionet aktive
        for session in self._all_sessions():
            session.connected = False
            try:
                session.conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
        log.info("Serveri u ndal. Mirupafshim!")

    # ------------------------------------------------------------------
    # Banner info
    # ------------------------------------------------------------------
    def _print_banner(self) -> None:
        print(
            f"\n"
            f"{'='*60}\n"
            f"  Encrypted Messaging Server  –  Nënshkrimet dhe Çelësat\n"
            f"{'='*60}\n"
            f"  Adresa      : {self.host}:{self.port}\n"
            f"  Kapaciteti  : {self.max_clients} klientë\n"
            f"  Enkriptimi  : RSA-OAEP / SHA-256  ({KEY_SIZE}-bit)\n"
            f"  Firma       : RSA-PSS  / SHA-256\n"
            f"  Gjurma RSA  : {self.fingerprint}\n"
            f"{'='*60}\n"
            f"  Shtyp Ctrl+C për të ndalur serverin.\n"
            f"{'='*60}\n"
        )


# ---------------------------------------------------------------------------
# Analiza e argumenteve CLI
# ---------------------------------------------------------------------------
def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="server.py",
        description="Encrypted Messaging Server – Nënshkrimet dhe Çelësat",
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"Adresa dëgjuese (default: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Porti dëgjues (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--max-clients",
        type=int,
        default=DEFAULT_MAX_CLIENTS,
        dest="max_clients",
        help=f"Numri maksimal i klientëve njëkohësishtë (default: {DEFAULT_MAX_CLIENTS})",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Hyrja kryesore
# ---------------------------------------------------------------------------
def main() -> int:
    args = _parse_args()

    if not (1 <= args.port <= 65535):
        log.critical(f"Numri i portit '{args.port}' është i pavlefshëm (1–65535).")
        return 1

    if args.max_clients < 1:
        log.critical("--max-clients duhet të jetë të paktën 1.")
        return 1

    server = EncryptedServer(
        host=args.host,
        port=args.port,
        max_clients=args.max_clients,
    )
    server.start()
    return 0


if __name__ == "__main__":
    sys.exit(main())
