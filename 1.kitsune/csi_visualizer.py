import streamlit as st
import matplotlib.pyplot as plt
from CSIKit.reader import get_reader
from CSIKit.util import csitools

# Set page title
st.set_page_config(page_title='CSI Visualizer')

# Add a title
st.title('CSI Visualizer')

# File uploader
uploaded_file = st.file_uploader('Choose a PCAP file', type='pcap')

if uploaded_file is not None:
    # Save the uploaded file temporarily
    with open('temp.pcap', 'wb') as f:
        f.write(uploaded_file.getvalue())

    # Read the PCAP file using CSIKit
    my_reader = get_reader('temp.pcap')
    csi_data = my_reader.read_file('temp.pcap', scaled=True)
    csi_matrix, no_frames, no_subcarriers = csitools.get_CSI(csi_data)

    # Visualize the CSI matrix
    fig, ax = plt.subplots()
    im = ax.imshow(abs(csi_matrix), aspect='auto', cmap='jet', interpolation='nearest')
    ax.set_xlabel('Subcarrier Index')
    ax.set_ylabel('Frame Index')
    ax.set_title('CSI Matrix')
    fig.colorbar(im, ax=ax)

    # Display the plot using Streamlit
    st.pyplot(fig)

    # Display additional information
    st.write(f'Number of frames: {no_frames}')
    st.write(f'Number of subcarriers: {no_subcarriers}')