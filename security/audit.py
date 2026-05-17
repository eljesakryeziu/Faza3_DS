import logging
from datetime import datetime

logging.basicConfig(
    filename="security.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)


def log_security_event(event_type, details):
    """
    Logs security-related events.
    """

    message = f"[{event_type}] {details}"
    logging.info(message)


def log_failed_validation(input_data):
    """
    Logs invalid or suspicious input attempts.
    """

    message = f"[VALIDATION_FAILED] Invalid input detected: {input_data}"
    logging.warning(message)


def log_signature_failure(client_id):
    """
    Logs failed digital signature verifications.
    """

    message = f"[SIGNATURE_ERROR] Signature verification failed for client: {client_id}"
    logging.error(message)


def log_connection(client_address):
    """
    Logs new client connections.
    """

    message = f"[NEW_CONNECTION] Client connected: {client_address}"
    logging.info(message)


def log_disconnection(client_address):
    """
    Logs disconnected clients.
    """

    message = f"[DISCONNECTED] Client disconnected: {client_address}"
    logging.info(message)
