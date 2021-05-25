/*
 * Copyright 2015-2021 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package org.minidns.record;

import org.minidns.constants.DnssecConstants.DigestAlgorithm;
import org.minidns.constants.DnssecConstants.SignatureAlgorithm;
import org.minidns.constants.svcbservicekeys.ServiceKeySpecification;
import org.minidns.constants.svcbservicekeys.UnrecognizedServiceKey;
import org.minidns.dnsname.DnsName;
import org.minidns.record.NSEC3.HashAlgorithm;
import org.minidns.record.Record.TYPE;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import static org.minidns.Assert.assertCsEquals;
import static org.minidns.Assert.assertArrayContentEquals;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * These are some tests for all records.
 *
 * The tests main purpose is to test if the output of toByteArray() is parsed into it's original value.
 *
 * Additionally, toString() is tested to be RFC compliant.
 */
public class RecordsTest {
    @Test
    public void testARecord() throws Exception {
        A a = new A(new byte[] {127, 0, 0, 1});
        assertEquals("127.0.0.1", a.toString());
        assertEquals(TYPE.A, a.getType());
        byte[] ab = a.toByteArray();
        a = A.parse(new DataInputStream(new ByteArrayInputStream(ab)));
        assertArrayEquals(new byte[] {127, 0, 0, 1}, a.getIp());
    }

    @Test
    public void testSVCBRecord() throws Exception {
        Set<ServiceKeySpecification<?>> params = new TreeSet<>();
        params.add(new UnrecognizedServiceKey(new byte[1], 6));
        params.add(new UnrecognizedServiceKey(new byte[1], 1));
        params.add(new UnrecognizedServiceKey(new byte[1], 3));
        SVCB svcb = new SVCB(1, DnsName.from("example.com"), params);

        assertEquals(TYPE.SVCB, svcb.getType());

        // The keys should be ordered ascending
        String expectedString = "1 example.com alpn=\"nopläintêxt\" port=\"numbers like 1 and very, very long text with spaces in it.\" ipv6hint=\"testing\" 65281=\"unknown\"";
        assertEquals(expectedString, svcb.toString());
        byte[] svcbb = svcb.toByteArray();
        svcb = SVCB.parse(new DataInputStream(new ByteArrayInputStream(svcbb)), svcb.length(), svcbb);
        assertEquals(expectedString, svcb.toString());
    }

    @Test
    public void testARecordInvalidIp() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> 
            new A(new byte[42])
        );
    }

    @Test
    public void testAAAARecord() throws Exception {
        AAAA aaaa = new AAAA(new byte[] {0x20, 0x01, 0x0d, (byte) 0xb8, (byte) 0x85, (byte) 0xa3, 0x08, (byte) 0xd3, 0x13, 0x19, (byte) 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x44});
        // Note: there are multiple valid representations of the IPv6 address due to optional reductions.
        assertEquals("2001:db8:85a3:8d3:1319:8a2e:370:7344", aaaa.toString());
        assertEquals(TYPE.AAAA, aaaa.getType());
        byte[] aaaab  = aaaa.toByteArray();
        aaaa = AAAA.parse(new DataInputStream(new ByteArrayInputStream(aaaab)));
        assertArrayEquals(new byte[] {0x20, 0x01, 0x0d, (byte) 0xb8, (byte) 0x85, (byte) 0xa3, 0x08, (byte) 0xd3, 0x13, 0x19, (byte) 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x44}, aaaa.getIp());
    }

    @Test
    public void testAAAARecordInvalidIp() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> 
            new AAAA(new byte[42])
        );
    }

    @Test
    public void testCnameRecord() throws Exception {
        CNAME cname = new CNAME("www.example.com");
        assertEquals("www.example.com.", cname.toString());
        assertEquals(TYPE.CNAME, cname.getType());
        byte[] cnameb = cname.toByteArray();
        cname = CNAME.parse(new DataInputStream(new ByteArrayInputStream(cnameb)), cnameb);
        assertCsEquals("www.example.com", cname.target);
    }

    @Test
    public void testDlvRecord() throws Exception {
        DLV dlv = new DLV(42, (byte) 8, (byte) 2, new byte[] {0x13, 0x37});
        assertEquals("42 RSASHA256 SHA256 1337", dlv.toString());
        assertEquals(TYPE.DLV, dlv.getType());
        byte[] dlvb = dlv.toByteArray();
        dlv = DLV.parse(new DataInputStream(new ByteArrayInputStream(dlvb)), dlvb.length);
        assertEquals(42, dlv.keyTag);
        assertEquals(SignatureAlgorithm.RSASHA256, dlv.algorithm);
        assertEquals(DigestAlgorithm.SHA256, dlv.digestType);
        assertArrayEquals(new byte[] {0x13, 0x37}, dlv.digest);
    }

    @SuppressWarnings("deprecation")
    @Test
    public void testDnskeyRecord() throws Exception {
        DNSKEY dnskey = new DNSKEY(DNSKEY.FLAG_ZONE, (byte) 3, (byte) 1, new byte[] {42});
        // TODO: Compare with real Base64 once done
        assertEquals("256 3 RSAMD5 " + dnskey.getKeyBase64(), dnskey.toString());
        assertEquals(TYPE.DNSKEY, dnskey.getType());
        byte[] dnskeyb = dnskey.toByteArray();
        dnskey = DNSKEY.parse(new DataInputStream(new ByteArrayInputStream(dnskeyb)), dnskeyb.length);
        assertEquals(256, dnskey.flags);
        assertEquals(3, dnskey.protocol);
        assertEquals(SignatureAlgorithm.RSAMD5, dnskey.algorithm);
        assertArrayEquals(new byte[] {42}, dnskey.getKey());
    }

    @Test
    public void testDsRecord() throws Exception {
        DS ds = new DS(42, (byte) 8, (byte) 2, new byte[] {0x13, 0x37});
        assertEquals("42 RSASHA256 SHA256 1337", ds.toString());
        assertEquals(TYPE.DS, ds.getType());
        byte[] dsb = ds.toByteArray();
        ds = DS.parse(new DataInputStream(new ByteArrayInputStream(dsb)), dsb.length);
        assertEquals(42, ds.keyTag);
        assertEquals(SignatureAlgorithm.RSASHA256, ds.algorithm);
        assertEquals(DigestAlgorithm.SHA256, ds.digestType);
        assertArrayEquals(new byte[] {0x13, 0x37}, ds.digest);
    }

    @Test
    public void testMxRecord() throws Exception {
        MX mx = new MX(10, "mx.example.com");
        assertEquals("10 mx.example.com.", mx.toString());
        assertEquals(TYPE.MX, mx.getType());
        byte[] mxb = mx.toByteArray();
        mx = MX.parse(new DataInputStream(new ByteArrayInputStream(mxb)), mxb);
        assertEquals(10, mx.priority);
        assertCsEquals("mx.example.com", mx.target);
    }

    @Test
    public void testNsecRecord() throws Exception {
        NSEC nsec = new NSEC("example.com", new TYPE[] {TYPE.A, TYPE.RRSIG, TYPE.DLV});
        assertEquals("example.com. A RRSIG DLV", nsec.toString());
        assertEquals(TYPE.NSEC, nsec.getType());
        byte[] nsecb = nsec.toByteArray();
        nsec = NSEC.parse(new DataInputStream(new ByteArrayInputStream(nsecb)), nsecb, nsecb.length);
        assertCsEquals("example.com", nsec.next);
        assertArrayContentEquals(new TYPE[] {TYPE.A, TYPE.RRSIG, TYPE.DLV}, nsec.types);
    }

    @Test
    public void testNsecTypeBitmapEmpty() throws IOException {
        List<TYPE> emptyTypes = Collections.emptyList();
        assertEquals(0, NSEC.readTypeBitMap(NSEC.createTypeBitMap(emptyTypes)).size());
    }

    @Test
    public void testNsec3Record() throws Exception {
        NSEC3 nsec3 = new NSEC3((byte) 1, (byte) 1, 1, new byte[] {0x13, 0x37}, new byte[] {0x42, 0x42, 0x42, 0x42, 0x42}, new TYPE[] {TYPE.A});
        assertEquals("SHA1 1 1 1337 89144GI2 A", nsec3.toString());
        assertEquals(TYPE.NSEC3, nsec3.getType());
        byte[] nsec3b = nsec3.toByteArray();
        nsec3 = NSEC3.parse(new DataInputStream(new ByteArrayInputStream(nsec3b)), nsec3b.length);
        assertEquals(HashAlgorithm.SHA1, nsec3.hashAlgorithm);
        assertEquals(1, nsec3.flags);
        assertEquals(1, nsec3.iterations);
        assertArrayEquals(new byte[] {0x13, 0x37}, nsec3.getSalt());
        assertArrayEquals(new byte[] {0x42, 0x42, 0x42, 0x42, 0x42}, nsec3.getNextHashed());
        assertArrayContentEquals(new TYPE[] {TYPE.A}, nsec3.types);

        assertEquals("SHA1 1 1 - ", new NSEC3((byte) 1, (byte) 1, 1, new byte[0], new byte[0], new TYPE[0]).toString());
    }

    @Test
    public void testNsec3ParamRecord() throws Exception {
        NSEC3PARAM nsec3param = new NSEC3PARAM((byte) 1, (byte) 1, 1, new byte[0]);
        assertEquals("SHA1 1 1 -", nsec3param.toString());
        assertEquals(TYPE.NSEC3PARAM, nsec3param.getType());
        byte[] nsec3paramb = nsec3param.toByteArray();
        nsec3param = NSEC3PARAM.parse(new DataInputStream(new ByteArrayInputStream(nsec3paramb)));
        assertEquals("SHA-1", nsec3param.hashAlgorithm.description);
        assertEquals(1, nsec3param.hashAlgorithmByte);
        assertEquals(1, nsec3param.flags);
        assertEquals(1, nsec3param.iterations);
        assertEquals(0, nsec3param.getSaltLength());

        assertEquals("SHA1 1 1 1337", new NSEC3PARAM((byte) 1, (byte) 1, 1, new byte[] {0x13, 0x37}).toString());
    }

    @Test
    public void testOpenpgpkeyRecord() throws Exception {
        OPENPGPKEY openpgpkey = new OPENPGPKEY(new byte[] {0x13, 0x37});
        assertEquals("Ezc=", openpgpkey.toString());
        assertEquals(TYPE.OPENPGPKEY, openpgpkey.getType());
        byte[] openpgpkeyb = openpgpkey.toByteArray();
        openpgpkey = OPENPGPKEY.parse(new DataInputStream(new ByteArrayInputStream(openpgpkeyb)), openpgpkeyb.length);
        assertArrayEquals(new byte[] {0x13, 0x37}, openpgpkey.getPublicKeyPacket());
    }

    @Test
    public void testPtrRecord() throws Exception {
        PTR ptr = new PTR("ptr.example.com");
        assertEquals("ptr.example.com.", ptr.toString());
        assertEquals(TYPE.PTR, ptr.getType());
        byte[] ptrb = ptr.toByteArray();
        ptr = PTR.parse(new DataInputStream(new ByteArrayInputStream(ptrb)), ptrb);
        assertCsEquals("ptr.example.com", ptr.target);
    }

    @Test
    public void testRrsigRecord() throws Exception {
        RRSIG rrsig = new RRSIG(TYPE.A, (byte) 8, (byte) 2, 3600, new Date(1000), new Date(0), 42, "example.com", new byte[] {42});
        // TODO: Compare with real Base64 once done
        assertEquals("A RSASHA256 2 3600 19700101000001 19700101000000 42 example.com. " + rrsig.getSignatureBase64(), rrsig.toString());
        assertEquals(TYPE.RRSIG, rrsig.getType());
        byte[] rrsigb = rrsig.toByteArray();
        rrsig = RRSIG.parse(new DataInputStream(new ByteArrayInputStream(rrsigb)), rrsigb, rrsigb.length);
        assertEquals(TYPE.A, rrsig.typeCovered);
        assertEquals(SignatureAlgorithm.RSASHA256, rrsig.algorithm);
        assertEquals(2, rrsig.labels);
        assertEquals(3600, rrsig.originalTtl);
        assertEquals(new Date(1000), rrsig.signatureExpiration);
        assertEquals(new Date(0), rrsig.signatureInception);
        assertEquals(42, rrsig.keyTag);
        assertCsEquals("example.com", rrsig.signerName);
        assertArrayEquals(new byte[] {42}, rrsig.getSignature());
    }

    @Test
    public void testSoaRecord() throws Exception {
        SOA soa = new SOA("sns.dns.icann.org", "noc.dns.icann.org", 2015060341, 7200, 3600, 1209600, 3600);
        assertEquals("sns.dns.icann.org. noc.dns.icann.org. 2015060341 7200 3600 1209600 3600", soa.toString());
        assertEquals(TYPE.SOA, soa.getType());
        byte[] soab = soa.toByteArray();
        soa = SOA.parse(new DataInputStream(new ByteArrayInputStream(soab)), soab);
        assertCsEquals("sns.dns.icann.org", soa.mname);
        assertCsEquals("noc.dns.icann.org", soa.rname);
        assertEquals(2015060341, soa.serial);
        assertEquals(7200, soa.refresh);
        assertEquals(3600, soa.retry);
        assertEquals(1209600, soa.expire);
        assertEquals(3600, soa.minimum);
    }

    @Test
    public void testSrvRecord() throws Exception {
        SRV srv = new SRV(30, 31, 5222, "hermes.jabber.org");
        assertEquals("30 31 5222 hermes.jabber.org.", srv.toString());
        assertEquals(TYPE.SRV, srv.getType());
        byte[] srvb = srv.toByteArray();
        srv = SRV.parse(new DataInputStream(new ByteArrayInputStream(srvb)), srvb);
        assertEquals(30, srv.priority);
        assertEquals(31, srv.weight);
        assertEquals(5222, srv.port);
        assertCsEquals("hermes.jabber.org", srv.target);
    }

    @Test
    public void testTlsaRecord() throws Exception {
        TLSA tlsa = new TLSA((byte) 1, (byte) 1, (byte) 1, new byte[] {0x13, 0x37});
        assertEquals("1 1 1 1337", tlsa.toString());
        assertEquals(TYPE.TLSA, tlsa.getType());
        byte[] tlsab = tlsa.toByteArray();
        tlsa = TLSA.parse(new DataInputStream(new ByteArrayInputStream(tlsab)), tlsab.length);
        assertEquals(1, tlsa.certUsageByte);
        assertEquals(1, tlsa.selectorByte);
        assertEquals(1, tlsa.matchingTypeByte);
        assertArrayEquals(new byte[] {0x13, 0x37}, tlsa.getCertificateAssociation());
    }
}
