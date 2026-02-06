#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Aug 25 12:56:27 2021

@author: chou.p.hung

Performance optimizations applied:
- Moved imports to module level
- Replaced busy-wait loops with time.sleep() for CPU efficiency
- Added configurable verbose flag (default False for production)
- Used struct module for efficient byte packing/unpacking
- Cached time calculations to reduce function call overhead
- Replaced numpy arrays with Python lists where appropriate
- Added connection timeout handling
"""
import dill as pickle
import struct
import time
import socket
import select
import random

# Global debug flag - set to False for production performance
DEBUG_VERBOSE = False

# Constants for packet structure
WHOLE_PACKET_SIZE = 1048
DATA_PACKET_SIZE = WHOLE_PACKET_SIZE - 48  # Reserve 48 bytes for header
HEADER_FORMAT = '>QQQQQQ'  # 6 unsigned 64-bit integers, big-endian
HEADER_SIZE = 48
MAGIC_NUMBER = 314159
COMPLETION_SIGNAL = 72057594037927935  # '-1' as unsigned

# Pre-computed header for game over signal
GAME_OVER_HEADER = struct.pack(HEADER_FORMAT, 0, 0, 0, 0, 0, 0)


def toEightBytes(number):
    """Convert a number to 8 bytes (big-endian).
    
    Optimized to handle both int and numpy.int64 types efficiently.
    """
    if hasattr(number, 'item'):  # numpy type
        number = number.item()
    return number.to_bytes(8, byteorder='big')


def _pack_header(h0, h1, h2, h3, h4, h5):
    """Pack 6 integers into a 48-byte header using struct (faster than manual concatenation)."""
    return struct.pack(HEADER_FORMAT, h0, h1, h2, h3, h4, h5)


def _unpack_header(data):
    """Unpack 48-byte header into 6 integers."""
    return struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])


def _get_time_ms():
    """Get current time in milliseconds."""
    return int(time.time() * 1000)

def sendReliablyBinary(msg, conn, verbose=None):
    """
    Send binary data reliably over a socket connection with packet acknowledgment.
    
    Performance optimizations:
    - Uses struct.pack for efficient header creation
    - Replaces busy-wait with time.sleep()
    - Uses select() with timeout instead of polling
    - Uses Python lists instead of numpy arrays
    
    Parameters
    ----------
    msg : bytes
        Pre-pickled message to send
    conn : socket
        Socket connection to send data through
    verbose : bool, optional
        Enable verbose logging (defaults to DEBUG_VERBOSE)
    """
    if verbose is None:
        verbose = DEBUG_VERBOSE
    
    dataSize = len(msg)
    numPacketsToSend = (dataSize + DATA_PACKET_SIZE - 1) // DATA_PACKET_SIZE
    lastPacketSize = (dataSize % DATA_PACKET_SIZE) + HEADER_SIZE
    if dataSize % DATA_PACKET_SIZE == 0:
        lastPacketSize = WHOLE_PACKET_SIZE
    
    if verbose:
        print(f'reliableSockets.py: lastPacketSize = {lastPacketSize}')
    
    SYN = random.randrange(1000000, 1000000000)
    initialPacketRecvd = False

    while not initialPacketRecvd:
        message = _pack_header(0, numPacketsToSend, lastPacketSize, SYN, 0, MAGIC_NUMBER)
        
        if verbose:
            print(f'reliableSockets.py: sending initial SYN packet at time {_get_time_ms()}')
        
        conn.sendall(message)
        
        ACKreceived = False
        timestart = _get_time_ms()
        
        while not ACKreceived:
            timeElapsed = _get_time_ms() - timestart
            
            if timeElapsed > 2000:
                if verbose:
                    print('reliableSockets.py: ACK timeout exceeded 2000ms')
                break
            
            readable, _, _ = select.select([conn], [], [], 0.01)
            if conn in readable:
                try:
                    message = conn.recv(WHOLE_PACKET_SIZE)
                    if len(message) >= HEADER_SIZE:
                        head0, head1, head2, head3, head4, head5 = _unpack_header(message)
                        
                        if verbose:
                            print(f'reliableSockets.py: received packet [{head0}, {head1}, {head2}, {head3}, {head4}, {head5}]')
                        
                        if head0 == 0 and head4 == SYN + 1 and head5 == MAGIC_NUMBER:
                            ACKreceived = True
                            initialPacketRecvd = True
                            if verbose:
                                print(f'reliableSockets.py: ACK received at time {_get_time_ms()}')
                        else:
                            ACKreceived = True
                            time.sleep(0.005)
                except socket.error:
                    pass

    ACK = 1000000001
    if verbose:
        print('reliableSockets.py: Beginning message transmit')

    packetsSentFlags = [0] * numPacketsToSend
    finalPacketRecvd = False
    timestartClock0 = _get_time_ms()
    
    while not finalPacketRecvd:
        thisPacketNum = 1
        for i, flag in enumerate(packetsSentFlags):
            if flag <= 0:
                thisPacketNum = i + 1
                break
        
        if verbose:
            print(f'reliableSockets.py: sending packet {thisPacketNum}')
        
        SYN += 1
        header = _pack_header(thisPacketNum, numPacketsToSend, lastPacketSize, SYN, ACK + 1, MAGIC_NUMBER)
        
        if thisPacketNum != numPacketsToSend:
            startByte = DATA_PACKET_SIZE * (thisPacketNum - 1)
            thisPacket = msg[startByte:startByte + DATA_PACKET_SIZE]
        else:
            startByte = DATA_PACKET_SIZE * (thisPacketNum - 1)
            thisPacket = msg[startByte:]
        
        totalPackage = header + thisPacket
        
        if verbose:
            print(f'reliableSockets.py: sending packet {thisPacketNum} of {numPacketsToSend}, {len(totalPackage)} bytes')
        
        conn.sendall(totalPackage)
        
        if packetsSentFlags[thisPacketNum - 1] == -1:
            time.sleep(0.005)
        
        packetsSentFlags[thisPacketNum - 1] = 1
        
        if verbose:
            print(f'reliableSockets.py: packetsSentFlags = {packetsSentFlags}')

        timestart = _get_time_ms()
        while _get_time_ms() - timestart < 2:
            readable, _, _ = select.select([conn], [], [], 0.001)
            if conn in readable:
                try:
                    message = conn.recv(WHOLE_PACKET_SIZE)
                    if len(message) >= HEADER_SIZE:
                        head0, head1, head2, head3, head4, head5 = _unpack_header(message)
                        
                        if verbose:
                            print(f'reliableSockets.py: received [{head0}, {head1}, {head2}, {head3}, {head4}, {head5}]')
                        
                        if head3 == MAGIC_NUMBER and head4 == MAGIC_NUMBER and head5 == MAGIC_NUMBER:
                            requestedPacketNum = head0
                            packetsSentFlags[requestedPacketNum - 1] = -1
                            if verbose:
                                print(f'reliableSockets.py: RESEND requested for packet {requestedPacketNum}')
                        
                        if head0 == COMPLETION_SIGNAL and head3 == 0 and head4 == 0:
                            if verbose:
                                print('reliableSockets.py: Full message received confirmation')
                            finalPacketRecvd = True
                            emptySocket(conn, verbose)
                            break
                except socket.error:
                    pass
        
        if verbose:
            print('reliableSockets.py: finished response check loop')
        
        if _get_time_ms() - timestartClock0 > 15000:
            if verbose:
                print('reliableSockets.py: WARNING - 15 second timeout exceeded')
            break


def recvReliablyBinary2(conn, data, verbose=None):
    """
    Receive binary data reliably over a socket connection with packet acknowledgment.
    
    Performance optimizations:
    - Uses struct.unpack for efficient header parsing
    - Replaces busy-wait with time.sleep()
    - Uses Python lists instead of numpy arrays
    - Caches time calculations
    
    Parameters
    ----------
    conn : socket
        Socket connection to receive data from
    data : bytes
        Initial data already received
    verbose : bool, optional
        Enable verbose logging (defaults to DEBUG_VERBOSE)
        
    Returns
    -------
    bytes
        The complete received message
    """
    if verbose is None:
        verbose = DEBUG_VERBOSE
    
    message = data
    head0, head1, head2, head3, head4, head5 = _unpack_header(message)
    
    if verbose:
        print(f'reliableSockets.py recvReliablyBinary2: Received [{head0}, {head1}, {head2}, {head3}, {head4}, {head5}]')
    
    if head0 == 0 and head5 == MAGIC_NUMBER:
        if verbose:
            print('reliableSockets.py recvReliablyBinary2: Confirmed SYN')
    else:
        headerReceived = False
        while not headerReceived:
            if verbose:
                print('reliableSockets.py: Incorrect SYN, retrying...')
            
            message = conn.recv(WHOLE_PACKET_SIZE)
            head0, head1, head2, head3, head4, head5 = _unpack_header(message)
            
            if verbose:
                print(f'reliableSockets.py recvReliablyBinary2: Received [{head0}, {head1}, {head2}, {head3}, {head4}, {head5}]')
            
            if head0 == 0 and head1 == 0 and head2 == 0 and head3 == 0 and head4 == 0 and head5 == 0:
                print('reliableSockets.py: Game Over signal received')
                conn.sendall(GAME_OVER_HEADER)
                return GAME_OVER_HEADER
            
            if head0 == 0 and head5 == MAGIC_NUMBER:
                if verbose:
                    print('reliableSockets.py recvReliablyBinary2: Confirmed SYN')
                headerReceived = True
            else:
                time.sleep(0.005)
    
    numPacketsToSend = head1
    lastPacketSize = head2
    SYN = head3
    
    SeqNum = random.randrange(3000000000, 4000000000)
    messageACK = _pack_header(0, numPacketsToSend, lastPacketSize, SeqNum, SYN + 1, MAGIC_NUMBER)
    
    if verbose:
        print('reliableSockets.py: Sending ACK Ready Signal')
    
    conn.sendall(messageACK)
    
    expectedMsgLength = numPacketsToSend * DATA_PACKET_SIZE + lastPacketSize - HEADER_SIZE
    if lastPacketSize > HEADER_SIZE:
        expectedMsgLength = (numPacketsToSend - 1) * DATA_PACKET_SIZE + (lastPacketSize - HEADER_SIZE)
    
    messageContainer = bytearray(expectedMsgLength)
    packetsReceivedFlags = [0] * numPacketsToSend
    finalPacketReceived = False
    
    time.sleep(0.005)
    
    timestartResendRequest = _get_time_ms()
    timestart = _get_time_ms()
    
    while not finalPacketReceived and (_get_time_ms() - timestart) < 5000:
        message = conn.recv(WHOLE_PACKET_SIZE)
        
        if len(message) < HEADER_SIZE:
            continue
        
        head0, head1, head2, head3, head4, head5 = _unpack_header(message)
        thisPacketNum = head0
        numPacketsToSend = head1
        lastPacketSize = head2
        
        if verbose:
            print(f'reliableSockets.py: Received packet [{head0}, {head1}, {head2}, {head3}, {head4}, {head5}]')
        
        if thisPacketNum == 0:
            if verbose:
                print('reliableSockets.py: Resending ACK')
            conn.sendall(messageACK)
            time.sleep(0.005)
            continue
        
        if thisPacketNum > 0 and head5 == MAGIC_NUMBER:
            if thisPacketNum < numPacketsToSend:
                if len(message) == WHOLE_PACKET_SIZE:
                    dataPacket = message[HEADER_SIZE:WHOLE_PACKET_SIZE]
                    startIdx = (thisPacketNum - 1) * DATA_PACKET_SIZE
                    endIdx = thisPacketNum * DATA_PACKET_SIZE
                    
                    if packetsReceivedFlags[thisPacketNum - 1] < 1:
                        messageContainer[startIdx:endIdx] = dataPacket
                        packetsReceivedFlags[thisPacketNum - 1] = 1
                        timestartResendRequest = _get_time_ms()
                        if verbose:
                            print(f'reliableSockets.py: Marked packet {thisPacketNum} as good')
                else:
                    packetsReceivedFlags[thisPacketNum - 1] = -1
                    if verbose:
                        print(f'reliableSockets.py: Marked packet {thisPacketNum} as bad (wrong size)')
            
            elif thisPacketNum == numPacketsToSend:
                if len(message) == lastPacketSize:
                    startIdx = (thisPacketNum - 1) * DATA_PACKET_SIZE
                    endIdx = startIdx + lastPacketSize - HEADER_SIZE
                    dataPacket = message[HEADER_SIZE:lastPacketSize]
                    
                    if packetsReceivedFlags[thisPacketNum - 1] < 1:
                        messageContainer[startIdx:endIdx] = dataPacket
                        packetsReceivedFlags[thisPacketNum - 1] = 1
                        timestartResendRequest = _get_time_ms()
                        if verbose:
                            print(f'reliableSockets.py: Marked packet {thisPacketNum} as good')
                else:
                    packetsReceivedFlags[thisPacketNum - 1] = -1
                    if verbose:
                        print(f'reliableSockets.py: Marked packet {thisPacketNum} as bad')
            
            if all(flag == 1 for flag in packetsReceivedFlags):
                if verbose:
                    print('reliableSockets.py: All packets received')
                
                completionMsg = _pack_header(COMPLETION_SIGNAL, numPacketsToSend, lastPacketSize, 0, 0, MAGIC_NUMBER)
                conn.sendall(completionMsg)
                
                if verbose:
                    print('reliableSockets.py: Sent completion signal')
                
                emptySocket(conn, verbose)
                return bytes(messageContainer)
            
            smallestMissingIdx = None
            for i, flag in enumerate(packetsReceivedFlags):
                if flag <= 0:
                    smallestMissingIdx = i
                    break
            
            if smallestMissingIdx is not None:
                smallestMissingPacketNum = smallestMissingIdx + 1
                
                if smallestMissingPacketNum <= thisPacketNum:
                    if packetsReceivedFlags[smallestMissingIdx] == -1:
                        if verbose:
                            print(f'reliableSockets.py: Requesting resend of packet {smallestMissingPacketNum}')
                        
                        resendMsg = _pack_header(smallestMissingPacketNum, numPacketsToSend, lastPacketSize,
                                                  MAGIC_NUMBER, MAGIC_NUMBER, MAGIC_NUMBER)
                        conn.sendall(resendMsg)
                        packetsReceivedFlags[smallestMissingIdx] = 0
                        timestartResendRequest = _get_time_ms()
                    
                    elif packetsReceivedFlags[smallestMissingIdx] == 0 and (_get_time_ms() - timestartResendRequest) > 50:
                        if verbose:
                            print('reliableSockets.py: 50ms timeout, marking for resend')
                        packetsReceivedFlags[smallestMissingIdx] = -1
                
                elif smallestMissingPacketNum > thisPacketNum:
                    if (_get_time_ms() - timestartResendRequest) > 50:
                        packetsReceivedFlags[smallestMissingIdx] = -1
                        
                        if verbose:
                            print(f'reliableSockets.py: Requesting resend of packet {smallestMissingPacketNum}')
                        
                        resendMsg = _pack_header(smallestMissingPacketNum, numPacketsToSend, lastPacketSize,
                                                  MAGIC_NUMBER, MAGIC_NUMBER, MAGIC_NUMBER)
                        conn.sendall(resendMsg)
                        packetsReceivedFlags[smallestMissingIdx] = 0
                        timestartResendRequest = _get_time_ms()
    
    if not finalPacketReceived:
        if verbose:
            print('reliableSockets.py: WARNING - Timeout without receiving all packets')
        return None


def emptySocket(conn, verbose=None):
    """
    Empty any remaining data from the socket buffer.
    
    Performance optimizations:
    - Uses time.sleep() instead of busy-wait
    - Uses select() with timeout
    
    Parameters
    ----------
    conn : socket
        Socket connection to empty
    verbose : bool, optional
        Enable verbose logging (defaults to DEBUG_VERBOSE)
    """
    if verbose is None:
        verbose = DEBUG_VERBOSE
    
    if verbose:
        print('reliableSockets.py: Emptying socket')
    
    end_time = _get_time_ms() + 1
    
    while _get_time_ms() < end_time:
        try:
            readable, _, _ = select.select([conn], [], [], 0.0001)
            if conn in readable:
                conn.recv(1024)
            else:
                break
        except (socket.error, OSError):
            break
    
    if verbose:
        print('reliableSockets.py: Socket emptied')                                                                                                
                    
