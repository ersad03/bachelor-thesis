import os
import subprocess
import sys
import csv
import numpy as np
from scapy.all import *
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import platform
import concurrent.futures
import pyshark
import plotly.graph_objects as go

# Import the ns module
import netStat as ns

def generate_file_stats(file_path):
    stats = {
        "Packet Number": [],
        "IP": [],
        "IPv6": [],
        "TCP": [],
        "UDP": [],
        "ICMP": [],
        "ARP": []
    }

    cap = pyshark.FileCapture(file_path, only_summaries=True)

    for i, packet in enumerate(cap):
        stats["Packet Number"].append(i + 1)
        stats["IP"].append(1 if 'ip' in packet else 0)
        stats["IPv6"].append(1 if 'ipv6' in packet else 0)
        stats["TCP"].append(1 if 'tcp' in packet else 0)
        stats["UDP"].append(1 if 'udp' in packet else 0)
        stats["ICMP"].append(1 if 'icmp' in packet else 0)
        stats["ARP"].append(1 if 'arp' in packet else 0)

    cap.close()
    return stats

# FE class
class FE:
    def get_features(self):
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.process_packet, i) for i in range(self.limit)]
            features = [f.result() for f in concurrent.futures.as_completed(futures)]
        return [f for f in features if f is not None]

    def process_packet(self, packet_index):
        feature_vector = self.get_next_vector(packet_index)
        if not any(feature_vector):
            return None
        return feature_vector

    def get_num_features(self):
        return len(self.nstat.getNetStatHeaders())

    def __init__(self, file):
        self.file = file
        self.path = file.name
        self.limit = np.inf
        self.parse_type = None  # unknown
        self.curPacketIndx = 0
        self.tsvin = None  # used for parsing TSV file
        self.pyshark_cap = None  # used for parsing pcap with pyshark

        # Class attribute assignments
        maxHost = 100000000000
        maxSess = 100000000000
        self.nstat = ns.netStat(np.nan, maxHost, maxSess)

        # Prep pcap
        self.__prep__()

    def _get_tshark_path(self):
        if platform.system() == 'Windows':
            return r'C:\Program Files\Wireshark\tshark.exe'  # Using a raw string literal
        else:
            system_path = os.environ['PATH']
            for path in system_path.split(os.pathsep):
                filename = os.path.join(path, 'tshark')
                if os.path.isfile(filename):
                    return filename
        return ''

    def __prep__(self):
        # Find file
        if not os.path.isfile(self.path):
            print(f"File: {self.path} does not exist")
            raise Exception()

        # Check file type
        file_type = self.path.split('.')[-1]

        self._tshark = self._get_tshark_path()
        # If file is TSV (pre-parsed by wireshark script)
        if file_type == "tsv":
            self.parse_type = "tsv"

        # If file is pcap
        elif file_type == "pcap" or file_type == 'pcapng':
            # Try parsing via tshark dll of wireshark (faster)
            if os.path.isfile(self._tshark):
                self.pcap2tsv_with_tshark()  # creates local tsv file
                self.path += ".tsv"
                self.parse_type = "tsv"
            else:  # Otherwise, parse with pyshark (faster than scapy)
                print("tshark not found. Trying pyshark...")
                self.parse_type = "pyshark"
        else:
            print(f"File: {self.path} is not a tsv or pcap file")
            raise Exception()

        # Open readers
        if self.parse_type == "tsv":
            maxInt = sys.maxsize
            decrement = True
            while decrement:
                # Decrease the maxInt value by factor 10 as long as the OverflowError occurs
                decrement = False
                try:
                    csv.field_size_limit(maxInt)
                except OverflowError:
                    maxInt = int(maxInt / 10)
                    decrement = True

            print("Counting lines in file...")
            num_lines = sum(1 for line in open(self.path))
            print(f"There are {num_lines} Packets.")
            self.limit = min(self.limit, num_lines - 1)
            self.tsvinf = open(self.path, 'rt', encoding="utf8")
            self.tsvin = csv.reader(self.tsvinf, delimiter='\t')
            next(self.tsvin)  # Move iterator past header

        else:  # pyshark
            print("Reading PCAP file via PyShark...")
            self.pyshark_cap = pyshark.FileCapture(self.path, only_summaries=True)
            self.limit = len(self.pyshark_cap)
            print(f"Loaded {self.limit} Packets.")

    def pcap2tsv_with_tshark(self):
        print('Parsing with tshark...')
        fields = "-e frame.time_epoch -e frame.len -e eth.src -e eth.dst -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e icmp.type -e icmp.code -e arp.opcode -e arp.src.hw_mac -e arp.src.proto_ipv4 -e arp.dst.hw_mac -e arp.dst.proto_ipv4 -e ipv6.src -e ipv6.dst"
        cmd = f'"{self._tshark}" -r "{self.path}" -T fields {fields} -E header=y -E occurrence=f > "{self.path}.tsv"'
        subprocess.call(cmd, shell=True)
        print(f"tshark parsing complete. File saved as: {self.path}.tsv")

    def get_next_vector(self, packet_index):
        if packet_index >= self.limit:
            return []

        # Parse next packet
        if self.parse_type == "tsv":
            row = next(self.tsvin, None)
            if row is None:
                return []

            IPtype = np.nan
            timestamp = row[0]
            framelen = row[1]
            srcIP = ''
            dstIP = ''
            if row[4] != '':  # IPv4
                srcIP = row[4]
                dstIP = row[5]
                IPtype = 0
            elif row[17] != '':  # IPv6
                srcIP = row[17]
                dstIP = row[18]
                IPtype = 1
            srcproto = row[6] + row[8]  # UDP or TCP port
            dstproto = row[7] + row[9]  # UDP or TCP port
            srcMAC = row[2]
            dstMAC = row[3]
            if srcproto == '':  # It's a L2/L1 level protocol
                if row[12] != '':  # Is ARP
                    srcproto = 'arp'
                    dstproto = 'arp'
                    srcIP = row[14]  # src IP (ARP)
                    dstIP = row[16]  # dst IP (ARP)
                    IPtype = 0
                elif row[10] != '':  # Is ICMP
                    srcproto = 'icmp'
                    dstproto = 'icmp'
                    IPtype = 0
                elif not any((srcIP, srcproto, dstIP, dstproto)):  # Some other protocol
                    srcIP = row[2]  # src MAC
                    dstIP = row[3]  # dst MAC

        elif self.parse_type == "pyshark":
            packet = self.pyshark_cap[packet_index]
            IPtype = np.nan
            timestamp = packet.sniff_timestamp
            framelen = packet.length
            srcIP = packet.source
            dstIP = packet.destination
            srcMAC = packet.eth.src
            dstMAC = packet.eth.dst
            srcproto = packet.transport_layer
            dstproto = packet.transport_layer
            if srcproto is None:
                srcproto = ''
                dstproto = ''
            if 'ip' in packet:
                IPtype = 0
            elif 'ipv6' in packet:
                IPtype = 1

        # Extract Features
        try:
            return self.nstat.updateGetStats(IPtype, srcMAC, dstMAC, srcIP, srcproto, dstIP, dstproto,
                                             int(framelen), float(timestamp))
        except Exception as e:
            print(e)
            return []

def main():
    # Streamlit configuration
    st.set_page_config(page_title="Network Traffic Feature Extraction", layout="wide")

    # File uploader
    uploaded_file = st.file_uploader("Choose a pcap or tsv file", type=["pcap", "tsv"])

    if uploaded_file is not None:
        # Display file details
        file_details = {
            "FileName": uploaded_file.name,
            "FileType": uploaded_file.type,
            "FileSize": uploaded_file.size
        }
        st.write(file_details)

        # Generate file statistics
        file_stats = generate_file_stats(uploaded_file.name)

        # Create a line chart using Plotly
        fig = go.Figure()

        for protocol in ["IP", "IPv6", "TCP", "UDP", "ICMP", "ARP"]:
            fig.add_trace(go.Scatter(
                x=file_stats["Packet Number"],
                y=file_stats[protocol],
                name=protocol,
                mode='lines',
                line=dict(shape='hv')
            ))

        fig.update_layout(
            title="Protocol Distribution",
            xaxis_title="Packet Number",
            yaxis_title="Presence (1 = Yes, 0 = No)",
            legend_title="Protocols",
            font=dict(
                family="Arial",
                size=14,
                color="black"
            ),
            template="plotly_white"
        )

        # Display the chart using Streamlit
        st.plotly_chart(fig)

        # Create FE object
        fe = FE(uploaded_file)

        # Extract features
        features = fe.get_features()

        # Convert features to dataframe
        df = pd.DataFrame(features, columns=fe.nstat.getNetStatHeaders())

        # Display feature dataframe
        st.write("Feature Dataframe:")
        st.write(df)

        # Visualize data
        st.write("Data Visualization:")
        num_cols = df.select_dtypes(include=[np.number]).columns
        selected_cols = st.multiselect("Select columns for visualization", num_cols)

        if selected_cols:
            fig, ax = plt.subplots()
            for col in selected_cols:
                ax = df[col].plot(kind="line", ax=ax, label=col)
            ax.set_xlabel("Packet Index")
            ax.set_ylabel("Feature Value")
            ax.legend()
            st.pyplot(fig)

if __name__ == "__main__":
    main()