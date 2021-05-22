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
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.PriorityQueue;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.minidns.MiniDnsFuture;
import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnsqueryresult.DnsQueryResult;
import org.minidns.source.AbstractDnsDataSource;

/**
 * A DNS data sources that resolves requests via the network asynchronously.
 */
public class AsyncNetworkDataSource extends AbstractDnsDataSource {

    /**
     * The logger of this data source.
     */
    protected static final Logger LOGGER = Logger.getLogger(AsyncNetworkDataSource.class.getName());

    private static final int REACTOR_THREAD_COUNT = 1;

    private static final Queue<AsyncDnsRequest> INCOMING_REQUESTS = new ConcurrentLinkedQueue<>();

    private static final Selector SELECTOR;

    private static final Lock REGISTRATION_LOCK = new ReentrantLock();

    private static final Queue<SelectionKey> PENDING_SELECTION_KEYS = new ConcurrentLinkedQueue<>();

    private static final Thread[] REACTOR_THREADS = new Thread[REACTOR_THREAD_COUNT];

    private static final PriorityQueue<AsyncDnsRequest> DEADLINE_QUEUE = new PriorityQueue<>(16, new Comparator<AsyncDnsRequest>() {
        @Override
        public int compare(AsyncDnsRequest o1, AsyncDnsRequest o2) {
            if (o1.deadline > o2.deadline) {
                return 1;
            } else if (o1.deadline < o2.deadline) {
                return -1;
            }
            return 0;
        }
    });

    static {
        try {
            SELECTOR = Selector.open();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        for (int i = 0; i < REACTOR_THREAD_COUNT; i++) {
            Thread reactorThread = new Thread(new Reactor());
            reactorThread.setDaemon(true);
            reactorThread.setName("MiniDNS Reactor Thread #" + i);
            reactorThread.start();
            REACTOR_THREADS[i] = reactorThread;
        }
    }

    @Override
    public MiniDnsFuture<DnsQueryResult, IOException> queryAsync(DnsMessage message, InetAddress address, int port, OnResponseCallback onResponseCallback) {
        AsyncDnsRequest asyncDnsRequest = new AsyncDnsRequest(message, address, port, udpPayloadSize, this, onResponseCallback);
        INCOMING_REQUESTS.add(asyncDnsRequest);
        synchronized (DEADLINE_QUEUE) {
            DEADLINE_QUEUE.add(asyncDnsRequest);
        }
        SELECTOR.wakeup();
        return asyncDnsRequest.getFuture();
    }

    @Override
    public DnsQueryResult query(DnsMessage message, InetAddress address, int port) throws IOException {
        MiniDnsFuture<DnsQueryResult, IOException> future = queryAsync(message, address, port, null);
        try {
            return future.get();
        } catch (InterruptedException e) {
            // This should never happen.
            throw new AssertionError(e);
        } catch (ExecutionException e) {
            Throwable wrappedThrowable = e.getCause();
            if (wrappedThrowable instanceof IOException) {
                throw (IOException) wrappedThrowable;
            }
            // This should never happen.
            throw new AssertionError(e);
        }
    }

    SelectionKey registerWithSelector(SelectableChannel channel, int ops, Object attachment) throws ClosedChannelException {
        REGISTRATION_LOCK.lock();
        try {
            SELECTOR.wakeup();
            return channel.register(SELECTOR, ops, attachment);
        } finally {
            REGISTRATION_LOCK.unlock();
        }
    }

    void finished(AsyncDnsRequest asyncDnsRequest) {
        synchronized (DEADLINE_QUEUE) {
            DEADLINE_QUEUE.remove(asyncDnsRequest);
        }
    }

    void cancelled(AsyncDnsRequest asyncDnsRequest) {
        finished(asyncDnsRequest);
        // Wakeup since the async DNS request was removed from the deadline queue.
        SELECTOR.wakeup();
    }

    private static class Reactor implements Runnable {
        @Override
        public void run() {
            while (!Thread.interrupted()) {
                Collection<SelectionKey> mySelectedKeys = performSelect();
                handleSelectedKeys(mySelectedKeys);

                handlePendingSelectionKeys();

                handleIncomingRequests();
            }
        }

        private static void handleSelectedKeys(Collection<SelectionKey> selectedKeys) {
            for (SelectionKey selectionKey : selectedKeys) {
                ChannelSelectedHandler channelSelectedHandler = (ChannelSelectedHandler) selectionKey.attachment();
                SelectableChannel channel = selectionKey.channel();
                channelSelectedHandler.handleChannelSelected(channel, selectionKey);
            }
        }

        @SuppressWarnings("LockNotBeforeTry")
        private static Collection<SelectionKey> performSelect() {
            AsyncDnsRequest nearestDeadline = null;
            AsyncDnsRequest nextInQueue;

            synchronized (DEADLINE_QUEUE) {
                while ((nextInQueue = DEADLINE_QUEUE.peek()) != null) {
                    if (nextInQueue.wasDeadlineMissedAndFutureNotified()) {
                        // We notified the future, associated with the AsyncDnsRequest nearestDeadline,
                        // that the deadline has passed, hence remove it from the queue.
                        DEADLINE_QUEUE.poll();
                    } else {
                        // We found a nearest deadline that has not yet passed, break out of the loop.
                        nearestDeadline = nextInQueue;
                        break;
                    }
                }

            }

            long selectWait;
            if (nearestDeadline == null) {
                // There is no deadline, wait indefinitely in select().
                selectWait = 0;
            } else {
                // There is a deadline in the future, only block in select() until the deadline.
                selectWait = nextInQueue.deadline - System.currentTimeMillis();
                if (selectWait < 0) {
                    // We already have a missed deadline. Do not call select() and handle the tasks which are past their
                    // deadline.
                    return Collections.emptyList();
                }
            }

            List<SelectionKey> selectedKeys;
            int newSelectedKeysCount;
            synchronized (SELECTOR) {
                // Ensure that a wakeup() in registerWithSelector() gives the corresponding
                // register() in the same method the chance to actually register the channel. In
                // other words: This construct ensure that there is never another select()
                // between a corresponding wakeup() and register() calls.
                // See also https://stackoverflow.com/a/1112809/194894
                REGISTRATION_LOCK.lock();
                REGISTRATION_LOCK.unlock();

                try {
                    newSelectedKeysCount = SELECTOR.select(selectWait);
                } catch (IOException e) {
                    LOGGER.log(Level.WARNING, "IOException while using select()", e);
                    return Collections.emptyList();
                }

                if (newSelectedKeysCount == 0) {
                    return Collections.emptyList();
                }

                Set<SelectionKey> selectedKeySet = SELECTOR.selectedKeys();
                for (SelectionKey selectionKey : selectedKeySet) {
                    selectionKey.interestOps(0);
                }

                selectedKeys = new ArrayList<>(selectedKeySet.size());
                selectedKeys.addAll(selectedKeySet);
                selectedKeySet.clear();
            }

            int selectedKeysCount = selectedKeys.size();

            final Level LOG_LEVEL = Level.FINER;
            if (LOGGER.isLoggable(LOG_LEVEL)) {
                LOGGER.log(LOG_LEVEL, "New selected key count: " + newSelectedKeysCount + ". Total selected key count "
                        + selectedKeysCount);
            }

            int myKeyCount = selectedKeysCount / REACTOR_THREAD_COUNT;
            Collection<SelectionKey> mySelectedKeys = new ArrayList<>(myKeyCount);
            Iterator<SelectionKey> it = selectedKeys.iterator();
            for (int i = 0; i < myKeyCount; i++) {
                SelectionKey selectionKey = it.next();
                mySelectedKeys.add(selectionKey);
            }
            while (it.hasNext()) {
                // Drain to PENDING_SELECTION_KEYS
                SelectionKey selectionKey = it.next();
                PENDING_SELECTION_KEYS.add(selectionKey);
            }
            return mySelectedKeys;
        }

        private static void handlePendingSelectionKeys() {
            int pendingSelectionKeysSize = PENDING_SELECTION_KEYS.size();
            if (pendingSelectionKeysSize == 0) {
                return;
            }

            int myKeyCount = pendingSelectionKeysSize / REACTOR_THREAD_COUNT;
            Collection<SelectionKey> selectedKeys = new ArrayList<>(myKeyCount);
            for (int i = 0; i < myKeyCount; i++) {
                SelectionKey selectionKey = PENDING_SELECTION_KEYS.poll();
                if (selectionKey == null) {
                    // We lost a race :)
                    break;
                }
                selectedKeys.add(selectionKey);
            }

            if (!PENDING_SELECTION_KEYS.isEmpty()) {
                // There is more work in the pending selection keys queue, wakeup another thread to handle it.
                SELECTOR.wakeup();
            }

            handleSelectedKeys(selectedKeys);
        }

        private static void handleIncomingRequests() {
            int incomingRequestsSize = INCOMING_REQUESTS.size();
            if (incomingRequestsSize == 0) {
                return;
            }

            int myRequestsCount = incomingRequestsSize / REACTOR_THREAD_COUNT;
            Collection<AsyncDnsRequest> requests = new ArrayList<>(myRequestsCount);
            for (int i = 0; i < myRequestsCount; i++) {
                AsyncDnsRequest asyncDnsRequest = INCOMING_REQUESTS.poll();
                if (asyncDnsRequest == null) {
                    // We lost a race :)
                    break;
                }
                requests.add(asyncDnsRequest);
            }

            if (!INCOMING_REQUESTS.isEmpty()) {
                SELECTOR.wakeup();
            }

            for (AsyncDnsRequest asyncDnsRequest : requests) {
                asyncDnsRequest.startHandling();
            }
        }

    }

}
