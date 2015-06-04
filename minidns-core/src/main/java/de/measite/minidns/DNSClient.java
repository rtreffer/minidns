package de.measite.minidns;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;

import de.measite.minidns.dnsserverlookup.AndroidUsingExec;
import de.measite.minidns.dnsserverlookup.AndroidUsingReflection;
import de.measite.minidns.dnsserverlookup.DNSServerLookupMechanism;
import de.measite.minidns.dnsserverlookup.HardcodedDNSServerAddresses;

/**
 * A minimal DNS client for SRV/A/AAAA/NS and CNAME lookups, with IDN support.
 * This circumvents the missing javax.naming package on android.
 */
public class DNSClient extends AbstractDNSClient {

    static final List<DNSServerLookupMechanism> LOOKUP_MECHANISMS = new ArrayList<>();

    static {
        addDnsServerLookupMechanism(AndroidUsingExec.INSTANCE);
        addDnsServerLookupMechanism(AndroidUsingReflection.INSTANCE);
        addDnsServerLookupMechanism(HardcodedDNSServerAddresses.INSTANCE);
    }
    private int udpPayloadSize = 512;

    public DNSClient(DNSCache dnsCache) {
        super(dnsCache);
    }

    public DNSClient(final Map<Question, DNSMessage> cache) {
        super(cache);
    }

    @Override
    public DNSMessage query(Question q, InetAddress address, int port) throws IOException {
        // See if we have the answer to this question already cached
        DNSMessage dnsMessage = (cache == null) ? null : cache.get(q);
        if (dnsMessage != null) {
            return dnsMessage;
        }

        DNSMessage message = new DNSMessage();
        message.setQuestions(new Question[]{q});
        message.setRecursionDesired(true);
        message.setId(random.nextInt());
        message.announceUdpPayloadSize(Math.min(udpPayloadSize, bufferSize));
        byte[] buf = message.toArray();

        dnsMessage = rawQueryUdp(address, port, buf);
        if (dnsMessage.getId() != message.getId()) {
            return null;
        }

        if (dnsMessage.isTruncated()) {
            dnsMessage = rawQueryTcp(address, port, buf);
        }

        if (dnsMessage.getId() != message.getId()) {
            return null;
        }
        for (Record record : dnsMessage.getAnswers()) {
            if (record.isAnswer(q)) {
                if (cache != null) {
                    cache.put(q, dnsMessage);
                }
                break;
            }
        }
        return dnsMessage;
    }

    private DNSMessage rawQueryUdp(InetAddress address, int port, byte[] buf) throws IOException {
        // TOOD Use a try-with-resource statement here once miniDNS minimum
        // required Android API level is >= 19
        DatagramSocket socket = null;
        try {
            socket = new DatagramSocket();
            DatagramPacket packet = new DatagramPacket(buf, buf.length,
                    address, port);
            socket.setSoTimeout(timeout);
            socket.send(packet);
            packet = new DatagramPacket(new byte[bufferSize], bufferSize);
            socket.receive(packet);
            return new DNSMessage(packet.getData());
        } finally {
            if (socket != null) {
                socket.close();
            }
        }
    }

    private DNSMessage rawQueryTcp(InetAddress address, int port, byte[] buf) throws IOException {
        // TOOD Use a try-with-resource statement here once miniDNS minimum
        // required Android API level is >= 19
        Socket socket = null;
        try {
            socket = new Socket(address, port);
            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
            dos.writeShort(buf.length);
            dos.write(buf);
            dos.flush();
            DataInputStream dis = new DataInputStream(socket.getInputStream());
            int length = dis.readUnsignedShort();
            byte[] data = new byte[length];
            dis.read(data);
            return new DNSMessage(data);
        } finally {
            if (socket != null) {
                socket.close();
            }
        }
    }

    /**
     * Query the system DNS server for one entry.
     * @param q The question section of the DNS query.
     * @return The response (or null on timeout/error).
     */
    public DNSMessage query(Question q) {
        // While this query method does in fact re-use query(Question, String)
        // we still do a cache lookup here in order to avoid unnecessary
        // findDNS()calls, which are expensive on Android. Note that we do not
        // put the results back into the Cache, as this is already done by
        // query(Question, String).
        DNSMessage message = (cache == null) ? null : cache.get(q);
        if (message != null) {
            return message;
        }

        String dnsServer[] = findDNS();
        for (String dns : dnsServer) {
            try {
                message = query(q, dns);
                if (message == null) {
                    continue;
                }
                if (message.getResponseCode() !=
                    DNSMessage.RESPONSE_CODE.NO_ERROR) {
                    continue;
                }
                for (Record record: message.getAnswers()) {
                    if (record.isAnswer(q)) {
                        return message;
                    }
                }
            } catch (IOException ioe) {
                LOGGER.log(Level.FINE, "IOException in query", ioe);
            }
        }
        return null;
    }

    /**
     * Retrieve a list of currently configured DNS servers.
     * @return The server array.
     */
    public static synchronized String[] findDNS() {
        String[] res = null;
        for (DNSServerLookupMechanism mechanism : LOOKUP_MECHANISMS) {
            res = mechanism.getDnsServerAddresses();
            if (res != null) {
                break;
            }
        }
        return res;
    }

    public static synchronized void addDnsServerLookupMechanism(DNSServerLookupMechanism dnsServerLookup) {
        LOOKUP_MECHANISMS.add(dnsServerLookup);
        Collections.sort(LOOKUP_MECHANISMS);
    }

    public static synchronized boolean removeDNSServerLookupMechanism(DNSServerLookupMechanism dnsServerLookup) {
        return LOOKUP_MECHANISMS.remove(dnsServerLookup);
    }

    public int getUdpPayloadSize() {
        return udpPayloadSize;
    }

    public void setUdpPayloadSize(int udpPayloadSize) {
        this.udpPayloadSize = udpPayloadSize;
    }
}