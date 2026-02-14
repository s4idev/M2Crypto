#!/usr/bin/env python

"""
Unit tests for M2Crypto.ftpslib (FTP/TLS client).

This test suite covers FTP/TLS client functionality:
- FTP_TLS client creation
- SSL context handling
- Protocol operations (AUTH TLS, PROT P/C)
- Connection state management

Copyright (c) 2024 M2Crypto contributors. All rights reserved.
"""

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from M2Crypto import ftpslib, SSL, Rand


class FTPTLSTestCase(unittest.TestCase):
    """Test FTP_TLS client basic operations"""

    def test_ftp_tls_create(self):
        """Test creating FTP_TLS client instance"""
        ftp = ftpslib.FTP_TLS()
        self.assertIsNotNone(ftp)

    def test_ftp_tls_create_with_ssl_ctx(self):
        """Test creating FTP_TLS with custom SSL context"""
        ssl_ctx = SSL.Context('sslv23')
        ftp = ftpslib.FTP_TLS(ssl_ctx=ssl_ctx)
        self.assertIsNotNone(ftp)
        self.assertEqual(ftp.ssl_ctx, ssl_ctx)

    def test_ftp_tls_default_ssl_ctx(self):
        """Test FTP_TLS creates default SSL context"""
        ftp = ftpslib.FTP_TLS()
        self.assertIsNotNone(ftp.ssl_ctx)
        self.assertIsInstance(ftp.ssl_ctx, SSL.Context)

    def test_ftp_tls_initial_prot_state(self):
        """Test FTP_TLS initial protection state is clear"""
        ftp = ftpslib.FTP_TLS()
        self.assertEqual(ftp.prot, 0)

    def test_auth_ssl_not_implemented(self):
        """Test auth_ssl raises NotImplementedError"""
        ftp = ftpslib.FTP_TLS()
        self.assertRaises(NotImplementedError, ftp.auth_ssl)


class FTPTLSProtocolTestCase(unittest.TestCase):
    """Test FTP_TLS protocol constants"""

    def test_default_protocol_constant(self):
        """Test DEFAULT_PROTOCOL constant is defined"""
        self.assertEqual(ftpslib.DEFAULT_PROTOCOL, 'sslv23')


class FTPTLSContextTestCase(unittest.TestCase):
    """Test FTP_TLS SSL context management"""

    def test_custom_cipher_list(self):
        """Test FTP_TLS with custom cipher list in SSL context"""
        ssl_ctx = SSL.Context('sslv23')
        ssl_ctx.set_cipher_list('HIGH')
        ftp = ftpslib.FTP_TLS(ssl_ctx=ssl_ctx)
        self.assertIsNotNone(ftp)

    def test_custom_verify_mode(self):
        """Test FTP_TLS with custom verification mode"""
        ssl_ctx = SSL.Context('sslv23')
        ssl_ctx.set_verify(SSL.verify_peer, depth=9)
        ftp = ftpslib.FTP_TLS(ssl_ctx=ssl_ctx)
        self.assertIsNotNone(ftp)


class FTPTLSInheritanceTestCase(unittest.TestCase):
    """Test FTP_TLS inherits from ftplib.FTP"""

    def test_ftp_tls_is_ftp(self):
        """Test FTP_TLS is instance of FTP"""
        from ftplib import FTP
        ftp = ftpslib.FTP_TLS()
        self.assertIsInstance(ftp, FTP)

    def test_ftp_tls_has_ftp_methods(self):
        """Test FTP_TLS has standard FTP methods"""
        ftp = ftpslib.FTP_TLS()
        # Check for some standard FTP methods
        self.assertTrue(hasattr(ftp, 'connect'))
        self.assertTrue(hasattr(ftp, 'login'))
        self.assertTrue(hasattr(ftp, 'quit'))
        self.assertTrue(hasattr(ftp, 'retrlines'))


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(FTPTLSTestCase))
    suite.addTest(unittest.makeSuite(FTPTLSProtocolTestCase))
    suite.addTest(unittest.makeSuite(FTPTLSContextTestCase))
    suite.addTest(unittest.makeSuite(FTPTLSInheritanceTestCase))
    return suite


if __name__ == '__main__':
    Rand.load_file('randpool.dat', -1)
    unittest.TextTestRunner().run(suite())
    Rand.save_file('randpool.dat')
