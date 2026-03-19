import csv
import time
import argparse
import threading
from scapy.all import sniff, IP, TCP, UDP

################ Config ################
FLOW_TIMEOUT  = 120   # seconds of inactivity before a flow is exported
EXPIRY_EVERY  = 10    # how often (seconds) the expiry thread runs
OUTPUT_FILE   = "live_traffic.csv"

stop_event = threading.Event()
flows      = {}         
flows_lock = threading.Lock()

################ UNSW-NB15 columns ################
COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto",
    "state", "dur", "sbytes", "dbytes", "sttl", "dttl",
    "sloss", "dloss", "service", "sload", "dload",
    "spkts", "dpkts", "swin", "dwin", "stcpb", "dtcpb",
    "smeansz", "dmeansz", "trans_depth", "res_bdy_len",
    "sjit", "djit", "stime", "ltime", "sintpkt", "dintpkt",
    "tcprtt", "synack", "ackdat", "is_sm_ips_ports",
    "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login",
    "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst",
    "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "attack_cat", "label",
]

################ Lookup tables ################
PROTO_MAP = {6: "tcp", 17: "udp", 1: "icmp"}

SERVICE_MAP = {
    80: "http", 443: "https", 21: "ftp", 22: "ssh",
    23: "telnet", 25: "smtp", 53: "dns", 110: "pop3",
    143: "imap", 3306: "mysql", 3389: "rdp", 8080: "http",
}

TCP_FLAGS = {0x01: "F", 0x02: "S", 0x04: "R", 0x08: "P", 0x10: "A", 0x20: "U"}

################ Helper functions ################

# Return a canonical 5-tuple key, or None if not an IP packet
def getFlowKey(pkt):
    if not pkt.haslayer(IP):
        return None
    ip    = pkt[IP]
    proto = PROTO_MAP.get(ip.proto, str(ip.proto))
    sport = dport = 0
    if pkt.haslayer(TCP):
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif pkt.haslayer(UDP):
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    # Always put the lower IP first so both directions share one key
    if ip.src <= ip.dst:
        return (ip.src, ip.dst, sport, dport, proto)
    else:
        return (ip.dst, ip.src, dport, sport, proto)


#    Return a fresh flow stats dictionary 
def newFlow(key, timestamp):
    return {
        "key":           key,
        "stime":         timestamp,
        "ltime":         timestamp,
        "spkts":         0,   "dpkts":  0,
        "sbytes":        0,   "dbytes": 0,
        "sttl":          0,   "dttl":   0,
        "swin":          0,   "dwin":   0,
        "stcpb":         0,   "dtcpb":  0,
        "src_pkt_sizes": [],  "dst_pkt_sizes": [],
        "src_times":     [],  "dst_times":     [],
        "tcp_flags":     set(),
        "syn_time":      None,
        "synack_time":   None,
        "ack_time":      None,
        "service":       "-",
        "state":         "INT",
    }


# Mean absolute deviation of inter-arrival times (ms)
def meanJitter(times):
    if len(times) < 2:
        return 0.0
    iats = [abs(times[i] - times[i-1]) * 1000 for i in range(1, len(times))]
    return sum(iats) / len(iats)


# Mean inter-packet time (ms)
def meanIntPKT(times):
    if len(times) < 2:
        return 0.0
    iats = [(times[i] - times[i-1]) * 1000 for i in range(1, len(times))]
    return sum(iats) / len(iats)


def tcpStates(flags):
    if "R" in flags: return "RST"
    if "F" in flags: return "FIN"
    if "S" in flags and "A" in flags: return "CON"
    if "S" in flags: return "REQ"
    return "INT"


# Convert a flow stats dict into a UNSW-NB15 row dict.
def flowToRow(f):
    sip, dip, sport, dport, proto = f["key"]
    dur   = max(f["ltime"] - f["stime"], 1e-9)
    sload = (f["sbytes"] * 8) / dur
    dload = (f["dbytes"] * 8) / dur
    smean = int(sum(f["src_pkt_sizes"]) / len(f["src_pkt_sizes"])) if f["src_pkt_sizes"] else 0
    dmean = int(sum(f["dst_pkt_sizes"]) / len(f["dst_pkt_sizes"])) if f["dst_pkt_sizes"] else 0

    tcprtt = (f["ack_time"]    - f["syn_time"])    if f["syn_time"]    and f["ack_time"]    else 0.0
    synack = (f["synack_time"] - f["syn_time"])    if f["syn_time"]    and f["synack_time"] else 0.0
    ackdat = (f["ack_time"]    - f["synack_time"]) if f["synack_time"] and f["ack_time"]    else 0.0

    return {
        "srcip":            sip,
        "sport":            sport,
        "dstip":            dip,
        "dsport":           dport,
        "proto":            proto,
        "state":            f["state"],
        "dur":              round(dur, 6),
        "sbytes":           f["sbytes"],
        "dbytes":           f["dbytes"],
        "sttl":             f["sttl"],
        "dttl":             f["dttl"],
        "sloss":            0,
        "dloss":            0,
        "service":          f["service"],
        "sload":            round(sload, 4),
        "dload":            round(dload, 4),
        "spkts":            f["spkts"],
        "dpkts":            f["dpkts"],
        "swin":             f["swin"],
        "dwin":             f["dwin"],
        "stcpb":            f["stcpb"],
        "dtcpb":            f["dtcpb"],
        "smeansz":          smean,
        "dmeansz":          dmean,
        "trans_depth":      0,
        "res_bdy_len":      0,
        "sjit":             round(meanJitter(f["src_times"]), 4),
        "djit":             round(meanJitter(f["dst_times"]), 4),
        "stime":            round(f["stime"], 6),
        "ltime":            round(f["ltime"], 6),
        "sintpkt":          round(meanIntPKT(f["src_times"]), 4),
        "dintpkt":          round(meanIntPKT(f["dst_times"]), 4),
        "tcprtt":           round(tcprtt, 6),
        "synack":           round(synack, 6),
        "ackdat":           round(ackdat, 6),
        "is_sm_ips_ports":  int(sip == dip and sport == dport),
        "ct_state_ttl":     0,
        "ct_flw_http_mthd": 0,
        "is_ftp_login":     0,
        "ct_ftp_cmd":       0,
        "ct_srv_src":       0,
        "ct_srv_dst":       0,
        "ct_dst_ltm":       0,
        "ct_src_ltm":       0,
        "ct_src_dport_ltm": 0,
        "ct_dst_sport_ltm": 0,
        "ct_dst_src_ltm":   0,
    }

################ Core packet handler ################

def processPacket(pkt):
    if not pkt.haslayer(IP):
        return

    now    = time.time()
    key    = getFlowKey(pkt)
    ip     = pkt[IP]
    is_fwd = (ip.src == key[0])   # True = src→dst direction
    plen   = len(pkt)

    with flows_lock:
        if key not in flows:
            flows[key] = newFlow(key, now)

        f = flows[key]
        f["ltime"] = now

        if is_fwd:
            f["spkts"]  += 1
            f["sbytes"] += plen
            f["sttl"]    = ip.ttl
            f["src_times"].append(now)
            f["src_pkt_sizes"].append(plen)
        else:
            f["dpkts"]  += 1
            f["dbytes"] += plen
            f["dttl"]    = ip.ttl
            f["dst_times"].append(now)
            f["dst_pkt_sizes"].append(plen)

        if pkt.haslayer(TCP):
            tcp        = pkt[TCP]
            flag_chars = {name for bit, name in TCP_FLAGS.items() if tcp.flags & bit}
            f["tcp_flags"].update(flag_chars)

            # Track TCP handshake timestamps
            if "S" in flag_chars and "A" not in flag_chars:        # SYN
                f["syn_time"] = now
                f["stcpb" if is_fwd else "dtcpb"] = tcp.seq
            elif "S" in flag_chars and "A" in flag_chars:           # SYN-ACK
                f["synack_time"] = now
                f["dtcpb"] = tcp.seq
            elif "A" in flag_chars and f["synack_time"] and not f["ack_time"]:  # ACK
                f["ack_time"] = now

            f["swin" if is_fwd else "dwin"] = tcp.window
            f["state"] = tcpStates(f["tcp_flags"])

        # Service from well-known port numbers
        f["service"] = SERVICE_MAP.get(key[3]) or SERVICE_MAP.get(key[2], "-")

################ CSV helpers ################

def createCSV(path):
    with open(path, "w", newline="") as fh:
        csv.DictWriter(fh, fieldnames=COLUMNS).writeheader()
    print(f"[+] Output: {path}")


def appendRows(path, rows):
    with open(path, "a", newline="") as fh:
        csv.DictWriter(fh, fieldnames=COLUMNS).writerows(rows)


# Export timed-out (or all) flows to CSV and remove them
def expireFlows(path, force_all=False):
    now = time.time()
    with flows_lock:
        expired = [k for k, f in flows.items()
                   if force_all or (now - f["ltime"]) > FLOW_TIMEOUT]
        rows = [flowToRow(flows.pop(k)) for k in expired]

    if rows:
        appendRows(path, rows)
        print(f"[+] Exported {len(rows)} flow(s) | active: {len(flows)}")

################ Background expiry thread ################

def expiry_worker(path):
    while not stop_event.is_set():
        time.sleep(EXPIRY_EVERY)
        expireFlows(path)

################ Main ################

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface",   default=None,        help="Network interface")
    parser.add_argument("--output",  default=OUTPUT_FILE, help="Output CSV path")
    parser.add_argument("--timeout", default=0, type=int, help="Capture seconds (0=infinite)")
    parser.add_argument("--count",   default=0, type=int, help="Max packets (0=infinite)")
    parser.add_argument("--filter",  default="ip",        help="BPF filter")
    args = parser.parse_args()

    createCSV(args.output)

    t = threading.Thread(target=expiry_worker, args=(args.output,), daemon=True)
    t.start()

    print(f"[+] Capturing on {args.iface or 'default'} | filter: {args.filter}")
    print("    Ctrl+C to stop.\n")

    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            prn=processPacket,
            store=False,
            timeout=args.timeout or None,
            count=args.count or 0,
        )
    except KeyboardInterrupt:
        print("\n[!] Stopped.")
    finally:
        stop_event.set()
        print("[+] Flushing remaining flows …")
        expireFlows(args.output, force_all=True)
        print(f"[✓] Saved → {args.output}")


if __name__ == "__main__":
    main()