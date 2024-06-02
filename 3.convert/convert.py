import streamlit as st
import pandas as pd
import os
from multiprocessing import Process, Queue
from scapy.all import rdpcap

def extract_features(packet, packet_count):
    packet_info = {
        'No.': packet_count,
        'Time': packet.time,
        'Source': packet['IP'].src if packet.haslayer('IP') else '',
        'Destination': packet['IP'].dst if packet.haslayer('IP') else '',
        'Protocol': packet['IP'].proto if packet.haslayer('IP') else '',
        'Length': len(packet),
        'Info': str(packet.summary()),
        'sttl': packet['IP'].ttl if packet.haslayer('IP') else '',
        'swin': packet['TCP'].window if packet.haslayer('TCP') else '',
        'stcpb': packet['TCP'].seq if packet.haslayer('TCP') else '',
        'dtcpb': packet['TCP'].ack if packet.haslayer('TCP') else ''
    }
    return packet_info

def convert_pcap_to_csv(pcap_file_path, output_csv_path, queue):
    try:
        packets = rdpcap(pcap_file_path)
        packet_list = []
        packet_count = 0

        for packet in packets:
            packet_count += 1
            packet_info = extract_features(packet, packet_count)
            packet_list.append(packet_info)

        df = pd.DataFrame(packet_list)
        df.to_csv(output_csv_path, index=False)
        queue.put("success")
    except Exception as e:
        queue.put(str(e))

def main():
    st.title('PCAP to CSV Converter with Feature Extraction')
    
    uploaded_file = st.file_uploader('Upload a PCAP file', type=['pcap', 'pcapng'])
    
    if uploaded_file is not None:
        # Save the uploaded file temporarily
        pcap_file_path = 'uploaded_file.pcap'
        with open(pcap_file_path, 'wb') as f:
            f.write(uploaded_file.getbuffer())
        
        st.write('File uploaded successfully.')
        
        # Convert the uploaded PCAP file to CSV
        output_csv_path = 'output.csv'
        queue = Queue()
        p = Process(target=convert_pcap_to_csv, args=(pcap_file_path, output_csv_path, queue))
        
        with st.spinner('Converting to CSV...'):
            p.start()
            p.join()

        result = queue.get()
        if result == "success":
            st.write('File converted to CSV successfully.')
            
            # Provide a download link for the CSV file
            with open(output_csv_path, 'rb') as f:
                st.download_button('Download CSV', f, file_name='output.csv')
            
            # Clean up temporary files
            os.remove(pcap_file_path)
            os.remove(output_csv_path)
        else:
            st.error(f"Error: {result}")

if __name__ == '__main__':
    main()
