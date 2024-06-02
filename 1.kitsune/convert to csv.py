import asyncio
import concurrent.futures
import pyshark
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
import streamlit as st

nest_asyncio.apply()

def render_csv_row(pkt_sh, pkt_sc, csv_rows):
    ether_pkt_sc = Ether(pkt_sc)
    if ether_pkt_sc.type != 0x800:
        return False

    ip_pkt_sc = ether_pkt_sc[IP]
    proto = ip_pkt_sc.fields['proto']

    if proto == 17:
        udp_pkt_sc = ip_pkt_sc[UDP]
        l4_payload_bytes = bytes(udp_pkt_sc.payload)
        l4_proto_name = 'UDP'
        l4_sport = udp_pkt_sc.sport
        l4_dport = udp_pkt_sc.dport
    elif proto == 6:
        tcp_pkt_sc = ip_pkt_sc[TCP]
        l4_payload_bytes = bytes(tcp_pkt_sc.payload)
        l4_proto_name = 'TCP'
        l4_sport = tcp_pkt_sc.sport
        l4_dport = tcp_pkt_sc.dport
    else:
        return False

    fmt = '{0}|{1}|{2}({3})|{4}|{5}:{6}|{7}:{8}|{9}|{10}'
    csv_rows.append(fmt.format(
        pkt_sh.no,
        pkt_sh.time,
        pkt_sh.protocol,
        l4_proto_name,
        pkt_sh.info,
        pkt_sh.source,
        l4_sport,
        pkt_sh.destination,
        l4_dport,
        pkt_sh.length,
        l4_payload_bytes.hex()
    ))
    return True

def pcap_to_csv(pcap_file):
    def process_pcap(pcap_file):
        pcap_pyshark = pyshark.FileCapture(pcap_file, only_summaries=True)
        pcap_pyshark.load_packets()
        pcap_pyshark.reset()

        csv_rows = []
        frame_num = 0
        ignored_packets = 0

        for (pkt_scapy, _) in RawPcapReader(pcap_file):
            try:
                pkt_pyshark = pcap_pyshark.next_packet()
                frame_num += 1
                if not render_csv_row(pkt_pyshark, pkt_scapy, csv_rows):
                    ignored_packets += 1
            except StopIteration:
                break

        pcap_pyshark.close()

        return "\n".join(csv_rows)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future = executor.submit(process_pcap, pcap_file)
        csv_result = future.result()

    return csv_result

# Streamlit interface
st.title("PCAP to CSV Converter")
uploaded_file = st.file_uploader("Upload a PCAP/PCAPNG file", type=["pcap", "pcapng"])

if uploaded_file:
    st.info("Converting...")
    with st.spinner("Converting..."):
        csv_result = pcap_to_csv(uploaded_file)
        st.success("Conversion completed!")
        st.download_button(
            label="Download CSV",
            data=csv_result,
            file_name="output.csv",
            mime="text/csv"
        )
