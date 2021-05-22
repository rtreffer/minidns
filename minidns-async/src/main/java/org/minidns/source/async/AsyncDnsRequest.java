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
package org.minidns.source.async;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.Channel;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Future;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.minidns.MiniDnsException;
import org.minidns.MiniDnsFuture;
import org.minidns.MiniDnsFuture.InternalMiniDnsFuture;
import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnsqueryresult.DnsQueryResult;
import org.minidns.dnsqueryresult.DnsQueryResult.QueryMethod;
import org.minidns.dnsqueryresult.StandardDnsQueryResult;
import org.minidns.source.DnsDataSource.OnResponseCallback;
import org.minidns.source.AbstractDnsDataSource.QueryMode;
import org.minidns.util.MultipleIoException;

/**
 * A DNS request that is performed asynchronously.
 */
public class AsyncDnsRequest {

    private static final Logger LOGGER = Logger.getLogger(AsyncDnsRequest.class.getName());

    private final InternalMiniDnsFuture<DnsQueryResult, IOException> future = new InternalMiniDnsFuture<DnsQueryResult, IOException>() {
        @SuppressWarnings("UnsynchronizedOverridesSynchronized")
        @Override
        public boolean cancel(boolean mayInterruptIfRunning) {
            boolean res = super.cancel(mayInterruptIfRunning);
            cancelAsyncDnsRequest();
            return res;
        }
    };

    private final DnsMessage request;

    private final int udpPayloadSize;

    private final InetSocketAddress socketAddress;

    private final AsyncNetworkDataSource asyncNds;

    private final OnResponseCallback onResponseCallback;

    private final boolean skipUdp;

    private ByteBuffer writeBuffer;

    private List<IOException> exceptions;

    private SelectionKey selectionKey;

    final long deadline;

    /**
     * Creates a new AsyncDnsRequest instance.
     *
     * @param request the DNS message of the request.
     * @param inetAddress The IP address of the DNS server to ask.
     * @param port The port of the DNS server to ask.
     * @param udpPayloadSize The configured UDP payload size.
     * @param asyncNds A reference to the {@link AsyncNetworkDataSource} instance manageing the requests.
     * @param onResponseCallback the optional callback when a response was received.
     */
    AsyncDnsRequest(DnsMessage request, InetAddress inetAddress, int port, int udpPayloadSize, AsyncNetworkDataSource asyncNds, OnResponseCallback onResponseCallback) {
        this.request = request;
        this.udpPayloadSize = udpPayloadSize;
        this.asyncNds = asyncNds;
        this.onResponseCallback = onResponseCallback;

        final QueryMode queryMode = asyncNds.getQueryMode();
        switch (queryMode) {
        case dontCare:
        case udpTcp:
            skipUdp = false;
            break;
        case tcp:
            skipUdp = true;
            break;
        default:
            throw new IllegalStateException("Unsupported query mode: " + queryMode);

        }
        deadline = System.currentTimeMillis() + asyncNds.getTimeout();
        socketAddress = new InetSocketAddress(inetAddress, port);
    }

    private void ensureWriteBufferIsInitialized() {
        if (writeBuffer != null) {
            if (!writeBuffer.hasRemaining()) {
                writeBuffer.rewind();
            }
            return;
        }
        writeBuffer = request.getInByteBuffer();
    }

    private synchronized void cancelAsyncDnsRequest() {
        if (selectionKey != null) {
            selectionKey.cancel();
        }
        asyncNds.cancelled(this);
    }

    private synchronized void registerWithSelector(SelectableChannel channel, int ops, ChannelSelectedHandler handler)
            throws ClosedChannelException {
        if (future.isCancelled()) {
            return;
        }
        selectionKey = asyncNds.registerWithSelector(channel, ops, handler);
    }

    private void addException(IOException e) {
        if (exceptions == null) {
            exceptions = new ArrayList<>(4);
        }
        exceptions.add(e);
    }

    private void gotResult(DnsQueryResult result) {
        if (onResponseCallback != null) {
            onResponseCallback.onResponse(request, result);
        }
        asyncNds.finished(this);
        future.setResult(result);
    }

    MiniDnsFuture<DnsQueryResult, IOException> getFuture() {
        return future;
    }

    boolean wasDeadlineMissedAndFutureNotified() {
        if (System.currentTimeMillis() < deadline) {
            return false;
        }

        future.setException(new IOException("Timeout"));
        return true;
    }

    void startHandling() {
        if (!skipUdp) {
            startUdpRequest();
        } else {
            startTcpRequest();
        }
    }

    private void abortRequestAndCleanup(Channel channel, String errorMessage, IOException exception) {
        if (exception == null) {
            // TODO: Can this case be removed? Is 'exception' ever null?
            LOGGER.info("Exception was null in abortRequestAndCleanup()");
            exception = new IOException(errorMessage);
        }
        LOGGER.log(Level.SEVERE, "Error connecting " + channel + ": " + errorMessage, exception);
        addException(exception);

        if (selectionKey != null) {
            selectionKey.cancel();
        }

        if (channel != null && channel.isOpen()) {
            try {
                channel.close();
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "Exception closing socket channel", e);
                addException(e);
            }
        }
    }

    private void abortUdpRequestAndCleanup(DatagramChannel datagramChannel, String errorMessage, IOException exception) {
        abortRequestAndCleanup(datagramChannel, errorMessage, exception);
        startTcpRequest();
    }

    private void startUdpRequest() {
        if (future.isCancelled()) {
            return;
        }

        DatagramChannel datagramChannel;
        try {
            datagramChannel = DatagramChannel.open();
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Exception opening datagram channel", e);
            addException(e);
            startTcpRequest();
            return;
        }

        try {
            datagramChannel.configureBlocking(false);
        } catch (IOException e) {
            abortUdpRequestAndCleanup(datagramChannel, "Exception configuring datagram channel", e);
            return;
        }

        try {
            datagramChannel.connect(socketAddress);
        } catch (IOException e) {
            abortUdpRequestAndCleanup(datagramChannel, "Exception connecting datagram channel to " + socketAddress, e);
            return;
        }

        try {
            registerWithSelector(datagramChannel, SelectionKey.OP_WRITE, new UdpWritableChannelSelectedHandler(future));
        } catch (ClosedChannelException e) {
            abortUdpRequestAndCleanup(datagramChannel, "Exception registering datagram channel for OP_WRITE", e);
            return;
        }
    }

    class UdpWritableChannelSelectedHandler extends ChannelSelectedHandler {

        UdpWritableChannelSelectedHandler(Future<?> future) {
            super(future);
        }

        @Override
        public void handleChannelSelectedAndNotCancelled(SelectableChannel channel, SelectionKey selectionKey) {
            DatagramChannel datagramChannel = (DatagramChannel) channel;

            ensureWriteBufferIsInitialized();

            try {
                datagramChannel.write(writeBuffer);
            } catch (IOException e) {
                abortUdpRequestAndCleanup(datagramChannel, "Exception writing to datagram channel", e);
                return;
            }

            if (writeBuffer.hasRemaining()) {
                try {
                    registerWithSelector(datagramChannel, SelectionKey.OP_WRITE, this);
                } catch (ClosedChannelException e) {
                    abortUdpRequestAndCleanup(datagramChannel, "Exception registering datagram channel for OP_WRITE", e);
                }
                return;
            }

            try {
                registerWithSelector(datagramChannel, SelectionKey.OP_READ, new UdpReadableChannelSelectedHandler(future));
            } catch (ClosedChannelException e) {
                abortUdpRequestAndCleanup(datagramChannel, "Exception registering datagram channel for OP_READ", e);
                return;
            }
        }

    }

    class UdpReadableChannelSelectedHandler extends ChannelSelectedHandler {

        UdpReadableChannelSelectedHandler(Future<?> future) {
            super(future);
        }

        final ByteBuffer byteBuffer = ByteBuffer.allocate(udpPayloadSize);

        @Override
        public void handleChannelSelectedAndNotCancelled(SelectableChannel channel, SelectionKey selectionKey) {
            DatagramChannel datagramChannel = (DatagramChannel) channel;

            try {
                datagramChannel.read(byteBuffer);
            } catch (IOException e) {
                abortUdpRequestAndCleanup(datagramChannel, "Exception reading from datagram channel", e);
                return;
            }

            selectionKey.cancel();
            try {
                datagramChannel.close();
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "Exception closing datagram channel", e);
                addException(e);
            }

            DnsMessage response;
            try {
                response = new DnsMessage(byteBuffer.array());
            } catch (IOException e) {
                abortUdpRequestAndCleanup(datagramChannel, "Exception constructing dns message from datagram channel", e);
                return;
            }

            if (response.id != request.id) {
                addException(new MiniDnsException.IdMismatch(request, response));
                startTcpRequest();
                return;
            }

            if (response.truncated) {
                startTcpRequest();
                return;
            }

            DnsQueryResult result = new StandardDnsQueryResult(socketAddress.getAddress(), socketAddress.getPort(),
                    QueryMethod.asyncUdp, request, response);
            gotResult(result);
        }
    }

    private void abortTcpRequestAndCleanup(SocketChannel socketChannel, String errorMessage, IOException exception) {
        abortRequestAndCleanup(socketChannel, errorMessage, exception);
        future.setException(MultipleIoException.toIOException(exceptions));
    }

    private void startTcpRequest() {
        SocketChannel socketChannel = null;
        try {
            socketChannel = SocketChannel.open();
        } catch (IOException e) {
            abortTcpRequestAndCleanup(socketChannel, "Exception opening socket channel", e);
            return;
        }

        try {
            socketChannel.configureBlocking(false);
        } catch (IOException e) {
            abortTcpRequestAndCleanup(socketChannel, "Exception configuring socket channel", e);
            return;
        }

        try {
            registerWithSelector(socketChannel, SelectionKey.OP_CONNECT, new TcpConnectedChannelSelectedHandler(future));
        } catch (ClosedChannelException e) {
            abortTcpRequestAndCleanup(socketChannel, "Exception registering socket channel", e);
            return;
        }

        try {
            socketChannel.connect(socketAddress);
        } catch (IOException e) {
            abortTcpRequestAndCleanup(socketChannel, "Exception connecting socket channel to " + socketAddress, e);
            return;
        }
    }

    class TcpConnectedChannelSelectedHandler extends ChannelSelectedHandler {

        TcpConnectedChannelSelectedHandler(Future<?> future) {
            super(future);
        }

        @Override
        public void handleChannelSelectedAndNotCancelled(SelectableChannel channel, SelectionKey selectionKey) {
            SocketChannel socketChannel = (SocketChannel) channel;

            boolean connected;
            try {
                connected = socketChannel.finishConnect();
            } catch (IOException e) {
                abortTcpRequestAndCleanup(socketChannel, "Exception finish connecting socket channel", e);
                return;
            }

            assert connected;

            try {
                registerWithSelector(socketChannel, SelectionKey.OP_WRITE, new TcpWritableChannelSelectedHandler(future));
            } catch (ClosedChannelException e) {
                abortTcpRequestAndCleanup(socketChannel, "Exception registering socket channel for OP_WRITE", e);
                return;
            }
        }

    }

    class TcpWritableChannelSelectedHandler extends ChannelSelectedHandler {

        TcpWritableChannelSelectedHandler(Future<?> future) {
            super(future);
        }

        /**
         * ByteBuffer array of length 2. First buffer is for the length of the DNS message, second one is the actual DNS message.
         */
        private ByteBuffer[] writeBuffers;

        @Override
        public void handleChannelSelectedAndNotCancelled(SelectableChannel channel, SelectionKey selectionKey) {
            SocketChannel socketChannel = (SocketChannel) channel;

            if (writeBuffers == null) {
                ensureWriteBufferIsInitialized();

                ByteBuffer messageLengthByteBuffer = ByteBuffer.allocate(2);
                int messageLength = writeBuffer.capacity();
                assert messageLength <= Short.MAX_VALUE;
                messageLengthByteBuffer.putShort((short) (messageLength & 0xffff));
                messageLengthByteBuffer.rewind();

                writeBuffers = new ByteBuffer[2];
                writeBuffers[0] = messageLengthByteBuffer;
                writeBuffers[1] = writeBuffer;
            }

            try {
                socketChannel.write(writeBuffers);
            } catch (IOException e) {
                abortTcpRequestAndCleanup(socketChannel, "Exception writing to socket channel", e);
                return;
            }

            if (moreToWrite()) {
                try {
                    registerWithSelector(socketChannel, SelectionKey.OP_WRITE, this);
                } catch (ClosedChannelException e) {
                    abortTcpRequestAndCleanup(socketChannel, "Exception registering socket channel for OP_WRITE", e);
                }
                return;
            }

            try {
                registerWithSelector(socketChannel, SelectionKey.OP_READ, new TcpReadableChannelSelectedHandler(future));
            } catch (ClosedChannelException e) {
                abortTcpRequestAndCleanup(socketChannel, "Exception registering socket channel for OP_READ", e);
                return;
            }
        }

        private boolean moreToWrite() {
            for (int i = 0; i < writeBuffers.length; i++) {
                if (writeBuffers[i].hasRemaining()) {
                    return true;
                }
            }
            return false;
        }
    }

    class TcpReadableChannelSelectedHandler extends ChannelSelectedHandler {

        TcpReadableChannelSelectedHandler(Future<?> future) {
            super(future);
        }

        final ByteBuffer messageLengthByteBuffer = ByteBuffer.allocate(2);

        ByteBuffer byteBuffer;

        @Override
        public void handleChannelSelectedAndNotCancelled(SelectableChannel channel, SelectionKey selectionKey) {
            SocketChannel socketChannel = (SocketChannel) channel;

            int bytesRead;
            if (byteBuffer == null) {
                try {
                    bytesRead = socketChannel.read(messageLengthByteBuffer);
                } catch (IOException e) {
                    abortTcpRequestAndCleanup(socketChannel, "Exception reading from socket channel", e);
                    return;
                }

                if (bytesRead < 0) {
                    abortTcpRequestAndCleanup(socketChannel, "Socket closed by remote host " + socketAddress, null);
                    return;
                }

                if (messageLengthByteBuffer.hasRemaining()) {
                    try {
                        registerWithSelector(socketChannel, SelectionKey.OP_READ, this);
                    } catch (ClosedChannelException e) {
                        abortTcpRequestAndCleanup(socketChannel, "Exception registering socket channel for OP_READ", e);
                    }
                    return;
                }

                messageLengthByteBuffer.rewind();
                short messageLengthSignedShort = messageLengthByteBuffer.getShort();
                int messageLength = messageLengthSignedShort & 0xffff;
                byteBuffer = ByteBuffer.allocate(messageLength);
            }

            try {
                bytesRead = socketChannel.read(byteBuffer);
            } catch (IOException e) {
                throw new Error(e);
            }

            if (bytesRead < 0) {
                abortTcpRequestAndCleanup(socketChannel, "Socket closed by remote host " + socketAddress, null);
                return;
            }

            if (byteBuffer.hasRemaining()) {
                try {
                    registerWithSelector(socketChannel, SelectionKey.OP_READ, this);
                } catch (ClosedChannelException e) {
                    abortTcpRequestAndCleanup(socketChannel, "Exception registering socket channel for OP_READ", e);
                }
                return;
            }

            selectionKey.cancel();
            try {
                socketChannel.close();
            } catch (IOException e) {
                addException(e);
            }

            DnsMessage response;
            try {
                response = new DnsMessage(byteBuffer.array());
            } catch (IOException e) {
                abortTcpRequestAndCleanup(socketChannel, "Exception creating DNS message form socket channel bytes", e);
                return;
            }

            if (request.id != response.id) {
                MiniDnsException idMismatchException = new MiniDnsException.IdMismatch(request, response);
                addException(idMismatchException);
                AsyncDnsRequest.this.future.setException(MultipleIoException.toIOException(exceptions));
                return;
            }

            DnsQueryResult result = new StandardDnsQueryResult(socketAddress.getAddress(), socketAddress.getPort(),
                    QueryMethod.asyncTcp, request, response);
            gotResult(result);
        }

    }

}
