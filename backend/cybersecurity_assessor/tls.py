"""Use the OS-native trust store for all TLS verification.

Python's ``ssl`` module ships with ``certifi``'s Mozilla bundle by default,
which doesn't include any private CAs your IT department may have deployed
(corporate MITM proxies, internal CAs, etc.). On those networks the
Anthropic SDK / httpx fail with
``[SSL: CERTIFICATE_VERIFY_FAILED] self-signed certificate in certificate chain``.

The ``truststore`` package patches Python's ``ssl`` module to consult the
operating system's certificate store instead — Windows ``CertStore``,
macOS ``Keychain``, Linux's OpenSSL config. Anything the OS already trusts
just works, with no app-side knowledge of the specific corporate root.

Import and call ``install()`` BEFORE constructing any ``httpx`` / ``anthropic``
client so the patched SSL context is in effect for the first connection.
"""

from __future__ import annotations


def install() -> None:
    """Patch Python's ssl module to use the OS-native trust store.

    No-op on systems where ``truststore`` is unavailable so the sidecar
    still boots; TLS errors then fall through to the hints surfaced by
    ``routes/settings.py``.
    """
    try:
        import truststore
    except ImportError:
        return
    truststore.inject_into_ssl()
