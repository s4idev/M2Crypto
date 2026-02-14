#!/usr/bin/env python

"""
Unit tests for M2Crypto.SSL basics.

This test suite covers basic SSL/TLS functionality:
- SSL Context creation and configuration
- SSL Cipher operations
- SSL Connection basics
- Protocol version handling
- Certificate and key loading

Copyright (c) 2024 M2Crypto contributors. All rights reserved.
"""

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from M2Crypto import SSL, Rand, m2, X509
import os


class SSLContextTestCase(unittest.TestCase):
    """Test SSL.Context creation and configuration"""

    def test_ctx_create_sslv23(self):
        """Test creating SSL context with SSLv23 protocol"""
        ctx = SSL.Context('sslv23')
        self.assertIsNotNone(ctx)

    def test_ctx_create_tlsv1(self):
        """Test creating SSL context with TLSv1 protocol"""
        ctx = SSL.Context('tlsv1')
        self.assertIsNotNone(ctx)

    def test_ctx_load_cert(self):
        """Test loading certificate into context"""
        ctx = SSL.Context('sslv23')
        ctx.load_cert('tests/server.pem')
        self.assertIsNotNone(ctx)

    def test_ctx_load_cert_chain(self):
        """Test loading certificate chain"""
        ctx = SSL.Context('sslv23')
        ctx.load_cert_chain('tests/server.pem')
        self.assertIsNotNone(ctx)

    def test_ctx_set_cipher_list(self):
        """Test setting cipher list"""
        ctx = SSL.Context('sslv23')
        ctx.set_cipher_list('ALL')
        self.assertIsNotNone(ctx)

    def test_ctx_set_verify(self):
        """Test setting verification mode"""
        ctx = SSL.Context('sslv23')
        ctx.set_verify(SSL.verify_none, depth=9)
        self.assertIsNotNone(ctx)

    def test_ctx_set_session_cache_mode(self):
        """Test setting session cache mode"""
        ctx = SSL.Context('sslv23')
        mode = m2.SSL_SESS_CACHE_SERVER
        ctx.set_session_cache_mode(mode)
        self.assertIsNotNone(ctx)

    def test_ctx_load_verify_locations(self):
        """Test loading CA certificates for verification"""
        ctx = SSL.Context('sslv23')
        ctx.load_verify_locations(cafile='tests/ca.pem')
        self.assertIsNotNone(ctx)


class SSLCipherTestCase(unittest.TestCase):
    """Test SSL.Cipher operations"""

    def setUp(self):
        self.ctx = SSL.Context('sslv23')

    def test_cipher_get_cipher_list(self):
        """Test getting available cipher list"""
        conn = SSL.Connection(self.ctx)
        ciphers = conn.get_cipher_list()
        self.assertIsNotNone(ciphers)
        self.assertIsInstance(ciphers, list)
        self.assertGreater(len(ciphers), 0)

    def test_cipher_set_cipher_list(self):
        """Test setting cipher list on connection"""
        conn = SSL.Connection(self.ctx)
        conn.set_cipher_list('DEFAULT')
        ciphers = conn.get_cipher_list()
        self.assertGreater(len(ciphers), 0)


class SSLConnectionTestCase(unittest.TestCase):
    """Test basic SSL.Connection operations"""

    def setUp(self):
        self.ctx = SSL.Context('sslv23')

    def test_connection_create(self):
        """Test creating SSL connection"""
        conn = SSL.Connection(self.ctx)
        self.assertIsNotNone(conn)

    def test_connection_set_accept_state(self):
        """Test setting connection to accept (server) state"""
        conn = SSL.Connection(self.ctx)
        conn.set_accept_state()
        self.assertIsNotNone(conn)

    def test_connection_set_connect_state(self):
        """Test setting connection to connect (client) state"""
        conn = SSL.Connection(self.ctx)
        conn.set_connect_state()
        self.assertIsNotNone(conn)

    def test_connection_get_state(self):
        """Test getting connection state string"""
        conn = SSL.Connection(self.ctx)
        state = conn.get_state_string()
        self.assertIsNotNone(state)
        self.assertIsInstance(state, str)


class SSLVerifyTestCase(unittest.TestCase):
    """Test SSL verification constants and modes"""

    def test_verify_constants(self):
        """Test that SSL verification constants are defined"""
        self.assertIsNotNone(SSL.verify_none)
        self.assertIsNotNone(SSL.verify_peer)
        self.assertIsNotNone(SSL.verify_fail_if_no_peer_cert)


class SSLProtocolTestCase(unittest.TestCase):
    """Test SSL/TLS protocol version handling"""

    def test_protocol_sslv23_available(self):
        """Test SSLv23 protocol is available"""
        ctx = SSL.Context('sslv23')
        self.assertIsNotNone(ctx)

    def test_protocol_tlsv1_available(self):
        """Test TLSv1 protocol is available"""
        ctx = SSL.Context('tlsv1')
        self.assertIsNotNone(ctx)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(SSLContextTestCase))
    suite.addTest(unittest.makeSuite(SSLCipherTestCase))
    suite.addTest(unittest.makeSuite(SSLConnectionTestCase))
    suite.addTest(unittest.makeSuite(SSLVerifyTestCase))
    suite.addTest(unittest.makeSuite(SSLProtocolTestCase))
    return suite


if __name__ == '__main__':
    Rand.load_file('randpool.dat', -1)
    unittest.TextTestRunner().run(suite())
    Rand.save_file('randpool.dat')
