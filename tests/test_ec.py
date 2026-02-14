#!/usr/bin/env python

"""
Unit tests for M2Crypto.EC (Elliptic Curve) module.

This comprehensive test suite covers:
- EC key generation and parameters
- ECDH (Elliptic Curve Diffie-Hellman) key exchange
- ECDSA (Elliptic Curve Digital Signature Algorithm)
- EC key loading and saving
- Public key operations

Copyright (c) 2024 M2Crypto contributors. All rights reserved.
"""

import sha
try:
    import unittest2 as unittest
except ImportError:
    import unittest

from M2Crypto import EC, BIO, Rand, m2


class ECTestCase(unittest.TestCase):
    """Comprehensive tests for M2Crypto.EC module"""
    
    privkey = 'tests/ec.priv.pem'
    pubkey = 'tests/ec.pub.pem'
    errkey = 'tests/rsa.priv.pem'
    
    data = sha.sha('Test data for EC signing').digest()

    def test_ec_curves_available(self):
        """Test that common EC curves are available"""
        # Test that we can create EC objects with common curves
        curves = [
            EC.NID_secp256k1,
            EC.NID_secp384r1,
            EC.NID_secp521r1,
            EC.NID_sect233k1,
        ]
        for curve_nid in curves:
            ec = EC.gen_params(curve_nid)
            self.assertIsNotNone(ec)

    def test_gen_params(self):
        """Test EC parameter generation"""
        ec = EC.gen_params(EC.NID_sect233k1)
        self.assertEqual(len(ec), 233)

    def test_gen_key(self):
        """Test EC key pair generation"""
        ec = EC.gen_params(EC.NID_sect233k1)
        ec.gen_key()
        # Key should be generated successfully
        self.assertIsNotNone(ec)

    def test_load_key(self):
        """Test loading EC private key from file"""
        ec = EC.load_key(self.privkey)
        self.assertEqual(len(ec), 233)

    def test_load_key_bad(self):
        """Test loading invalid key raises error"""
        self.assertRaises(ValueError, EC.load_key, self.errkey)

    def test_load_pub_key(self):
        """Test loading EC public key from file"""
        ec = EC.load_pub_key(self.pubkey)
        self.assertEqual(len(ec), 233)

    def test_load_pub_key_bad(self):
        """Test loading invalid public key raises error"""
        self.assertRaises(EC.ECError, EC.load_pub_key, self.errkey)

    def test_save_load_key(self):
        """Test saving and loading EC keys"""
        ec = EC.gen_params(EC.NID_secp256k1)
        ec.gen_key()
        
        # Save key to BIO
        bio = BIO.MemoryBuffer()
        ec.save_key_bio(bio, cipher=None)
        
        # Load key back
        bio.reset()
        ec2 = EC.load_key_bio(bio)
        self.assertIsNotNone(ec2)

    def test_save_load_pub_key(self):
        """Test saving and loading EC public keys"""
        ec = EC.gen_params(EC.NID_secp256k1)
        ec.gen_key()
        
        # Save public key to BIO
        bio = BIO.MemoryBuffer()
        ec.save_pub_key_bio(bio)
        
        # Load public key back
        bio.reset()
        ec2 = EC.load_pub_key_bio(bio)
        self.assertIsNotNone(ec2)

    def test_ecdh_compute_key(self):
        """Test ECDH key agreement/exchange"""
        # Generate two key pairs
        a = EC.load_key(self.privkey)
        b = EC.gen_params(EC.NID_sect233k1)
        b.gen_key()
        
        # Compute shared secrets
        ak = a.compute_dh_key(b.pub())
        bk = b.compute_dh_key(a.pub())
        
        # Shared secrets should be equal
        self.assertEqual(ak, bk)

    def test_ecdh_pubkey_from_der(self):
        """Test creating public key from DER format"""
        a = EC.gen_params(EC.NID_sect233k1)
        a.gen_key()
        b = EC.gen_params(EC.NID_sect233k1)
        b.gen_key()
        
        # Convert public key to DER and back
        a_pub_der = a.pub().get_der()
        a_pub = EC.pub_key_from_der(a_pub_der)
        
        # Compute shared keys
        ak = a.compute_dh_key(b.pub())
        bk = b.compute_dh_key(a_pub)
        
        self.assertEqual(ak, bk)

    def test_ecdsa_sign_verify_asn1(self):
        """Test ECDSA signing and verification with ASN.1 format"""
        ec = EC.load_key(self.privkey)
        
        # Sign data
        signature = ec.sign_dsa_asn1(self.data)
        
        # Verify signature
        self.assertTrue(ec.verify_dsa_asn1(self.data, signature))
        
        # Verification with wrong data should fail
        self.assertRaises(EC.ECError, ec.verify_dsa_asn1, signature, self.data)

    def test_ecdsa_sign_verify(self):
        """Test ECDSA signing and verification"""
        ec = EC.load_key(self.privkey)
        
        # Sign data
        r, s = ec.sign_dsa(self.data)
        
        # Verify signature
        self.assertTrue(ec.verify_dsa(self.data, r, s))
        
        # Verification with swapped r and s should fail
        self.assertFalse(ec.verify_dsa(self.data, s, r))

    def test_ecdsa_verify_with_pubkey(self):
        """Test ECDSA verification with public key only"""
        ec = EC.load_key(self.privkey)
        r, s = ec.sign_dsa(self.data)
        
        # Load public key and verify
        ec_pub = EC.load_pub_key(self.pubkey)
        self.assertTrue(ec_pub.verify_dsa(self.data, r, s))
        self.assertFalse(ec_pub.verify_dsa(self.data, s, r))

    def test_ec_init_junk(self):
        """Test EC initialization with invalid input"""
        self.assertRaises(TypeError, EC.EC, 'junk')

    def test_pub_key_operations(self):
        """Test public key extraction and operations"""
        ec = EC.gen_params(EC.NID_secp256k1)
        ec.gen_key()
        
        # Get public key
        pub = ec.pub()
        self.assertIsNotNone(pub)
        
        # Get DER representation
        pub_der = pub.get_der()
        self.assertIsNotNone(pub_der)
        self.assertIsInstance(pub_der, str)


def suite():
    return unittest.makeSuite(ECTestCase)


if __name__ == '__main__':
    Rand.load_file('randpool.dat', -1)
    unittest.TextTestRunner().run(suite())
    Rand.save_file('randpool.dat')
