from scapy.all import sniff, IP, ARP, ICMP, TCP, UDP

import pickle
import json
import numpy as np
from datetime import datetime
import time
import os


def write_json(new_data, filename="/home/wilhelm/eyeotdashboard/src/data/logs.json"):
    with open(filename, "r+") as file:
        file_data = json.load(file)
        file_data.append(new_data)
        file.seek(0)
        json.dump(file_data, file, indent=4)


packet = {

    "arp.opcode": 0,
    "arp.hw.size": 0,
    "icmp.checksum": 0,
    "icmp.seq_le": 0,
    "tcp.ack": 0,
    "tcp.checksum": 0,
    "tcp.connection.fin": 0,
    "tcp.connection.rst": 0,
    "tcp.connection.syn": 0,
    "tcp.connection.synack": 0,
    "tcp.flags": 0,
    "tcp.flags.ack": 0,
    "tcp.len": 0,
    "tcp.seq": 0,
    "udp.time_delta": 0,
    "mqtt.topic_len": 0,
    "mqtt.protoname-0": 0,
    "mqtt.protoname-MQTT": 0,
}

log = {
    "time": "",
    "class": "",
    "protocol": "",
    "src_ip": "",
    "dst_ip": "",
    "src_port": 0,
    "dst_port": 0,
    "action": "Blocked",
    "source": "Packets"
}
ctr = 0
t = 0
model = pickle.load(open("RF_Classifier3.sav", "rb"))


def scan(x):
    try:
        if x.haslayer(ARP):
            packet.update({"arp.opcode": x.getlayer(ARP).op})
            packet.update({"arp.hw.size": x.getlayer(ARP).hwlen})
        if x.haslayer(ICMP):
            packet.update({"icmp.checksum": x.getlayer(ICMP).chksum})
            packet.update({"icmp.seq_le": x.getlayer(ICMP).seq})
        if x.haslayer(TCP):
            packet.update({"tcp.ack": x.getlayer(TCP).ack})
            packet.update({"tcp.checksum": x.getlayer(TCP).chksum})
            packet.update({"tcp.seq": x.getlayer(TCP).seq})
            packet.update({"tcp.len": x.getlayer(TCP).window})
            packet.update({"tcp.flags": x.getlayer(TCP).flags.value})
            if x["TCP"].flags.value == 16:
                packet.update({"tcp.flags.ack": 1})
            elif x["TCP"].flags.value == 1:
                packet.update({"tcp.flags.ack": 1})
                packet.update({"tcp.connection.syn": 1})
            elif x["TCP"].flags.value == 4:
                packet.update({"tcp.connection.rst": 1})
            elif x["TCP"].flags.value == 2:
                packet.update({"tcp.connection.syn": 1})
            elif x["TCP"].flags.value == 25:
                packet.update({"tcp.flags.ack": 1})
                packet.update({"tcp.connection.fin": 1})
            elif x["TCP"].flags.value == 24:
                packet.update({"tcp.flags.ack": 1})
            elif x["TCP"].flags.value == 17:
                packet.update({"tcp.flags.ack": 1})
                packet.update({"tcp.connection.fin": 1})
            elif x["TCP"].flags.value == 18:
                packet.update({"tcp.flags.ack": 1})
                packet.update({"tcp.connection.synack": 1})
            elif x["TCP"].flags.value == 20:
                packet.update({"tcp.connection.rst": 1})
                packet.update({"tcp.flags.ack": 1})

        global t
        if t == 0:
            packet.update({"udp.time_delta": 0})
        else:
            packet.update({"udp.time_delta": x.time-t})
        t = x.time

        ###

        result = packet.values()
        l = list(result)
        X = np.array(l)
        y = model.predict([X])[0]
        if y == 6:
            print("Normal Traffic")
        if y != 6:
            log.update({"time": datetime.fromtimestamp(
                x.time).strftime('%d-%m-%y %H:%M:%S')})
            if x.haslayer(IP):
                log.update({"src_ip": x[IP].src})
                log.update({"dst_ip": x[IP].dst})
                #cmd = 'sudo ufw reject from {} to any'
                # os.system(cmd.format(x[IP].src))
            if x.haslayer(TCP) and not x.haslayer(UDP):
                log.update({"src_port": x[TCP].sport})
                log.update({"dst_port": x[TCP].dport})
            if x.haslayer(UDP) and not x.haslayer(TCP):
                log.update({"src_port": x[UDP].sport})
                log.update({"dst_port": x[UDP].dport})
            if not x.haslayer(UDP) and not x.haslayer(TCP):
                log.update({"src_port": "N/A"})
                log.update({"dst_port": "N/A"})
            if y == 0:
                atk = "BACKDOOR"
                prot = "TCP"
                print(atk+" Detected!")
                log.update({
                    "class": atk,
                    "protocol": prot,
                })
            elif y == 1:
                atk = "ICMP FLOOD"
                prot = "ICMP"
                print(atk+" Detected!")
                log.update({
                    "class": atk,
                    "protocol": prot,
                })
            elif y == 2:
                atk = "TCP SYN FLOOD"
                prot = "TCP"
                print(atk+" Detected!")
                log.update({
                    "class": atk,
                    "protocol": prot,
                })
            elif y == 3:
                atk = "UDP FLOOD"
                prot = "UDP"
                print(atk+" Detected!")
                log.update({
                    "class": atk,
                    "protocol": prot,
                })
            elif y == 4:
                atk = "OS FINGERPRINTING"
                prot = "TCP"
                print(atk+" Detected!")
                log.update({
                    "class": atk,
                    "protocol": prot,
                })
            elif y == 5:
                atk = "ARP SPOOFING"
                prot = "ARP"
                print(atk+" Detected!")
                log.update({
                    "class": atk,
                    "protocol": prot,
                })
            elif y == 7:
                atk = "PASSWORD CRACKING"
                prot = "TCP"
                print(atk+" Detected!")
                log.update({
                    "class": atk,
                    "protocol": prot,
                })
            elif y == 8:
                atk = "Port Scanning"
                prot = "TCP"
                print(atk+" Detected!")
                log.update({
                    "class": atk,
                    "protocol": prot,

                })
        global ctr
        ctr += 1
        print("{} packets sniffed".format(ctr))
        write_json(log)
    except Exception as e:
        print(f"caught {type(e)}: e")


cap = sniff(iface="vmnet1", prn=lambda x: scan(x), count=5)
