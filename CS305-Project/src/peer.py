import sys
import os
import time
import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import select
import util.simsocket as simsocket
import struct
import socket
import util.bt_utils as bt_utils
import hashlib
import argparse
import pickle

"""
This is CS305 project skeleton code.
Please refer to the example files - example/dumpreceiver.py and example/dumpsender.py - to learn how to play with this skeleton.
"""

BUF_SIZE = 1400
CHUNK_DATA_SIZE = 512 * 1024
HEADER_LEN = struct.calcsize("HBBHHII")
MAX_PAYLOAD = 1024

config = None
ex_sending_chunkhash = ""
ex_received_chunk = dict()
ex_downloading_chunkhash = ""
timeout = 0
list_addr = []
newsock = 0
inputTimeout = 0
ex_have = dict()
ex_sent = []
receive_num = 0
need_num = 0
last_receive_ihave = 0
start_time = 0


class addr(object):
    chunkhash = ""
    send_num = 1
    ack_num = 0
    win_size = 1
    ssthresh = 64
    ack_number = 0
    estimatedRTT = -1
    devRTT = -1
    used_win_size = 0
    win_point = []
    time_point = []


dict_addr = {}
dict_time = {}
send_to_addr = []
extra_send = {}
Peer_ack = {}
last_receive_time = {}
peer_addr = []
peer_data = {}


def process_download(sock, chunkfile, outputfile):
    '''
    if DOWNLOAD is used, the peer will keep getting files until it is done
    '''
    global ex_output_file, ignore_line, need_num
    global ex_received_chunk
    global ex_downloading_chunkhash
    need_num = 0
    ex_output_file = outputfile
    download_hash = bytes()
    with open(chunkfile, 'r') as cf:
        this_line = cf.readline().strip()

        while this_line:
            index, datahash_str = this_line.split(" ")
            ex_received_chunk[datahash_str] = bytes()
            ex_downloading_chunkhash = datahash_str
            need_num += 1
            # hex_str to bytes
            datahash = bytes.fromhex(datahash_str)
            download_hash = download_hash + datahash + b'\r\n'

            this_line = cf.readline().strip()
    # Step2: make WHOHAS pkt
    # |2byte magic|1byte type |1byte team|
    # |2byte  header len  |2byte pkt len |
    # |      4byte  seq                  |
    # |      4byte  ack                  |
    whohas_header = struct.pack("HBBHHII", socket.htons(52305), 35, 0, socket.htons(HEADER_LEN),
                                socket.htons(HEADER_LEN + len(download_hash)), socket.htonl(0), socket.htonl(0))
    whohas_pkt = whohas_header + download_hash

    # Step3: flooding whohas to all peers in peer list
    peer_list = config.peers
    for p in peer_list:
        if int(p[0]) != config.identity:
            sock.sendto(whohas_pkt, (p[1], int(p[2])))


def process_inbound_udp(sock):
    global list_addr, timeout, config, ex_sending_chunkhash, send_to_addr, ex_have, ex_sent, extra_send, Peer_ack
    global peer_addr, receive_num, last_receive_time, last_receive_ihave, start_time
    for i in range(len(list_addr)):
        a = dict_addr[list_addr[i]]
        a.used_win_size = min(a.used_win_size, a.send_num - a.ack_num)
        for j in range(a.ack_num + 1, a.send_num + 1):
            if dict_time.get(str(list_addr[i]) + str(j)) is not None:
                t = dict_time[str(list_addr[i]) + str(j)]
            else:
                return
            if timeout > 0 and time.time() - t > timeout:  # TODO:超时
                left = (j - 1) * MAX_PAYLOAD
                right = min(j * MAX_PAYLOAD, CHUNK_DATA_SIZE)
                next_data = config.haschunks[a.chunkhash][left: right]
                data_header = struct.pack("HBBHHII", socket.htons(52305), 35, 3, socket.htons(HEADER_LEN),
                                          socket.htons(HEADER_LEN + len(next_data)), socket.htonl(j), 0)
                dict_time[str(list_addr[i]) + str(j)] = time.time()
                sock.sendto(data_header + next_data, list_addr[i])
                a.used_win_size += 1
                a.win_size = 1
                a.ssthresh = max(a.ssthresh / 2, 2)
        if a.used_win_size <= a.win_size and a.send_num < 512:
            left = a.send_num * MAX_PAYLOAD
            right = min((a.send_num + 1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
            next_data = config.haschunks[a.chunkhash][left: right]
            # send next data
            data_header = struct.pack("HBBHHII", socket.htons(52305), 35, 3, socket.htons(HEADER_LEN),
                                      socket.htons(HEADER_LEN + len(next_data)), socket.htonl(a.send_num + 1), 0)
            sock.sendto(data_header + next_data, list_addr[i])
            dict_time[str(list_addr[i]) + str(a.send_num + 1)] = time.time()
            a.send_num += 1
            a.used_win_size += 1
        dict_addr[list_addr[i]] = a
    need_to_pop = []
    for add in last_receive_time:
        if time.time() - last_receive_time[add] > 15:
            download_hash = bytes()
            for i in range(len(extra_send[add])):
                download_hash = download_hash + extra_send[add][i] + b'\r\n'
            whohas_header = struct.pack("HBBHHII", socket.htons(52305), 35, 0, socket.htons(HEADER_LEN),
                                        socket.htons(HEADER_LEN + len(download_hash)), socket.htonl(0), socket.htonl(0))
            whohas_pkt = whohas_header + download_hash
            peer_list = config.peers
            for p in peer_list:
                if int(p[0]) != config.identity:
                    sock.sendto(whohas_pkt, (p[1], int(p[2])))
            need_to_pop.append(add)
    for i in need_to_pop:
        last_receive_time.pop(i)

    if len(peer_addr) == len(config.peers) - 1 or (
            last_receive_ihave != 0 and time.time() - last_receive_ihave > 5):  # 发送get，从type=1中拆分
        # sorting list_addr
        last_receive_ihave = 0
        for i in range(len(peer_addr)):
            for j in range(len(peer_addr) - i):
                if len(ex_have[peer_addr[i]]) > len(ex_have[peer_addr[i + j]]):
                    a = peer_addr[i + j]
                    b = peer_addr[i]
                    peer_addr[i] = b
                    peer_addr[i + j] = a
        # send back GET pkt
        for address in peer_addr:
            sending = False
            for chunk in ex_have[address]:
                if chunk not in ex_sent:
                    if extra_send.get(address) is None:
                        extra_send[address] = []
                    extra_send[address].append(chunk)
                    if sending:
                        continue
                    else:
                        sending = True
                        ex_sent.append(chunk)
                        if chunk == bytes():
                            continue
                        last_receive_time[address] = time.time()
                        get_header = struct.pack("HBBHHII", socket.htons(52305), 35, 2, socket.htons(HEADER_LEN),
                                                 socket.htons(HEADER_LEN + len(chunk)), socket.htonl(0),
                                                 socket.htonl(0))
                        get_pkt = get_header + chunk
                        sock.sendto(get_pkt, address)
        peer_addr = []
        ex_sent = []
    if newsock == 0:
        return
    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    Magic, Team, Type, hlen, plen, Seq, Ack = struct.unpack("HBBHHII", pkt[:HEADER_LEN])
    data = pkt[HEADER_LEN:]
    if Type == 1:
        # received an IHAVE pkt
        # see what chunk the sender has
        get_chunk_hash = data[:20]
        gch = get_chunk_hash.split(b'\r\n')
        if from_addr not in peer_addr:
            peer_addr.append(from_addr)
            ex_have[from_addr] = []
        for chunk in gch:
            ex_have[from_addr].append(chunk)
        last_receive_ihave = time.time()
    elif Type == 3:
        last_receive_time[from_addr] = time.time()
        if len(extra_send[from_addr]) == 0 or bytes.hex(extra_send[from_addr][0]) == '':
            return
        hascode = bytes.hex(extra_send[from_addr][0])
        Seq = socket.htonl(Seq)

        if from_addr not in Peer_ack:
            ex_received_chunk[hascode] += data
            Peer_ack.update({from_addr: Seq})
            peer_data.update({from_addr: [bytes()] * 1000})
        else:
            peer_data[from_addr][Seq] = data
            if Seq == Peer_ack[from_addr] + 1:
                while peer_data[from_addr][Peer_ack[from_addr] + 1] != bytes():
                    ex_received_chunk[hascode] += peer_data[from_addr][Peer_ack[from_addr] + 1]
                    Peer_ack[from_addr] += 1
                Seq = Peer_ack[from_addr]
            if Seq > Peer_ack[from_addr] + 1:
                Seq = Peer_ack[from_addr]

        # send back ACK
        Seq = socket.ntohl(Seq)
        ack_pkt = struct.pack("HBBHHII", socket.htons(52305), 35, 4, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN),
                              0, Seq)
        sock.sendto(ack_pkt, from_addr)

        # see if finished
        if len(ex_received_chunk[hascode]) == CHUNK_DATA_SIZE:
            last_receive_time.pop(from_addr)
            Peer_ack.pop(from_addr)
            peer_data.pop(from_addr)
            # finished downloading this chunkdata!
            # dump your received chunk to file in dict form using pickle

            # add to this peer's haschunk:
            config.haschunks[hascode] = ex_received_chunk[hascode]

            # continue sending get if the sender peer has multiple chunks need to send
            chunkHashList = extra_send[from_addr]
            chunkHashList.pop(0)
            extra_send.update({from_addr: chunkHashList})
            receive_num += 1
            if receive_num == need_num:
                with open(ex_output_file, "wb") as wf:
                    pickle.dump(ex_received_chunk, wf)
            if len(chunkHashList) != 0 and extra_send[from_addr][0] != bytes():
                get_header = struct.pack("HBBHHII", socket.htons(52305), 35, 2, socket.htons(HEADER_LEN),
                                         socket.htons(HEADER_LEN + len(extra_send[from_addr][0])), socket.htonl(0),
                                         socket.htonl(0))
                get_pkt = get_header + extra_send[from_addr][0]
                sock.sendto(get_pkt, from_addr)

            # you need to print "GOT" when finished downloading all chunks in a DOWNLOAD file
            print(f"GOT {ex_output_file}")

            # The following things are just for illustration, you do not need to print out in your design.
            sha1 = hashlib.sha1()
            sha1.update(ex_received_chunk[ex_downloading_chunkhash])
            received_chunkhash_str = sha1.hexdigest()
            print(f"Expected chunkhash: {ex_downloading_chunkhash}")
            print(f"Received chunkhash: {received_chunkhash_str}")
            success = ex_downloading_chunkhash == received_chunkhash_str
            print(f"Successful received: {success}")
            if success:
                print("Congrats! You have completed the example!")
            else:
                print("Example fails. Please check the example files carefully.")
    if Type == 0:
        # received an WHOHAS pkt
        # see what chunk the sender has
        if from_addr in list_addr:
            print(from_addr)
            return
        whohas_chunk_hash = data
        # bytes to hex_str
        ch_str = whohas_chunk_hash.split(b'\r\n')
        ihave_data = bytes()

        for i in range(len(ch_str)):
            if bytes.hex(ch_str[i]) in config.haschunks:
                ihave_data = ihave_data + ch_str[i] + b'\r\n'
        ihave_header = struct.pack("HBBHHII", socket.htons(52305), 35, 1, socket.htons(HEADER_LEN),
                                   socket.htons(HEADER_LEN + len(ihave_data)), socket.htonl(0),
                                   socket.htonl(0))
        ihave_pkt = ihave_header + ihave_data
        sock.sendto(ihave_pkt, from_addr)

    elif Type == 2:
        # received a GET pkt
        if bytes.hex(data) == '':
            return
        if send_to_addr.count(from_addr) == 0:
            send_to_addr.append(from_addr)
        list_addr.append(from_addr)
        a = addr()
        a.chunkhash = bytes.hex(data)
        dict_addr[from_addr] = a
        dict_time[str(from_addr) + str(1)] = time.time()
        chunk_data = config.haschunks[a.chunkhash][:MAX_PAYLOAD]
        # send back DATA
        data_header = struct.pack("HBBHHII", socket.htons(52305), 35, 3, socket.htons(HEADER_LEN),
                                  socket.htons(HEADER_LEN), socket.htonl(1), 0)
        sock.sendto(data_header + chunk_data, from_addr)

    elif Type == 4:
        # received an ACK pkt
        if list_addr.count(from_addr) == 0:
            return
        ack_num = socket.ntohl(Ack)
        print(from_addr)
        print(ack_num)
        a = dict_addr[from_addr]
        print(a.ack_num)
        print(a.ack_number)
        if ack_num > a.ack_num:
            a.used_win_size -= max(ack_num - a.ack_num - a.ack_number + 1, 1)
            a.used_win_size = max(a.used_win_size, 0)
        else:
            a.used_win_size = max(a.used_win_size - 1, 0)
        if (ack_num) * MAX_PAYLOAD >= CHUNK_DATA_SIZE:
            # finished
            plt.plot(a.time_point, a.win_point, color='blue')
            plt.xlabel('time(s)')
            plt.ylabel('Window Size')
            plt.savefig('myfig')
            a.win_point = []
            a.time_point = []
            print(f"finished sending {dict_addr[from_addr].chunkhash}")
            print(f"send to: {from_addr}")
            if list_addr.count(from_addr) > 0:
                list_addr.remove(from_addr)
            pass
        else:
            if ack_num == a.ack_num:
                a.ack_number += 1
                if a.ack_number == 3:  # TODO:三次ACK
                    left = a.ack_num * MAX_PAYLOAD
                    right = min((a.ack_num + 1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
                    next_data = config.haschunks[a.chunkhash][left: right]
                    data_header = struct.pack("HBBHHII", socket.htons(52305), 35, 3, socket.htons(HEADER_LEN),
                                              socket.htons(HEADER_LEN + len(next_data)), socket.htonl(a.ack_num + 1), 0)
                    dict_time[str(from_addr) + str(a.ack_num + 1)] = time.time()
                    sock.sendto(data_header + next_data, from_addr)
                    a.win_size = 1
                    a.ssthresh = max(a.ssthresh / 2, 2)
            else:
                if ack_num > a.ack_num:
                    a.ack_num = ack_num
                else:
                    return
                a.ack_number = 1
                if a.win_size < a.ssthresh:
                    a.win_size += 1
                else:
                    a.win_size += 1 / a.win_size
                a.win_point.append(a.win_size)
                a.time_point.append(time.time() - start_time)
                if inputTimeout == 0:
                    if a.estimatedRTT == -1:
                        a.estimatedRTT = time.time() - dict_time[str(from_addr) + str(a.ack_num)]
                        a.devRTT = a.estimatedRTT / 2
                    else:
                        a.estimatedRTT = a.estimatedRTT * 0.875 + (
                                time.time() - dict_time[str(from_addr) + str(a.ack_num)]) * 0.125
                        a.devRTT = a.devRTT * 0.75 + abs(time.time() - dict_time[
                            str(from_addr) + str(a.ack_num)] - a.estimatedRTT) * 0.25
                    timeout = a.estimatedRTT + 4 * a.devRTT
            dict_addr[from_addr] = a


def process_user_input(sock):
    command, chunkf, outf = input().split(' ')
    if command == 'DOWNLOAD':
        process_download(sock, chunkf, outf)
    else:
        pass


def peer_run(config):
    addr = (config.ip, config.port)
    sock = simsocket.SimSocket(config.identity, addr, verbose=config.verbose)
    global newsock, inputTimeout, timeout, start_time
    start_time = time.time()
    if config.timeout > 0:
        inputTimeout = 1
        timeout = config.timeout
    else:
        inputTimeout = 0
        timeout = 0
    try:
        while True:
            ready = select.select([sock, sys.stdin], [], [], 0.1)
            read_ready = ready[0]
            if len(read_ready) > 0:
                if sock in read_ready:
                    newsock = 1
                    process_inbound_udp(sock)
                if sys.stdin in read_ready:
                    process_user_input(sock)
            else:
                newsock = 0
                process_inbound_udp(sock)
                # No pkt nor input arrives during this period
                pass
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == '__main__':
    """
    -p: Peer list file, it will be in the form "*.map" like nodes.map.
    -c: Chunkfile, a dictionary dumped by pickle. It will be loaded automatically in bt_utils. The loaded dictionary has the form: {chunkhash: chunkdata}
    -m: The max number of peer that you can send chunk to concurrently. If more peers ask you for chunks, you should reply "DENIED"
    -i: ID, it is the index in nodes.map
    -v: verbose level for printing logs to stdout, 0 for no verbose, 1 for WARNING level, 2 for INFO, 3 for DEBUG.
    -t: pre-defined timeout. If it is not set, you should estimate timeout via RTT. If it is set, you should not change this time out.
        The timeout will be set when running test scripts. PLEASE do not change timeout if it set.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', type=str, help='<peerfile>     The list of all peers', default='nodes.map')
    parser.add_argument('-c', type=str, help='<chunkfile>    Pickle dumped dictionary {chunkhash: chunkdata}')
    parser.add_argument('-m', type=int, help='<maxconn>      Max # of concurrent sending')
    parser.add_argument('-i', type=int, help='<identity>     Which peer # am I?')
    parser.add_argument('-v', type=int, help='verbose level', default=0)
    parser.add_argument('-t', type=int, help="pre-defined timeout", default=0)
    args = parser.parse_args()

    config = bt_utils.BtConfig(args)
    peer_run(config)
