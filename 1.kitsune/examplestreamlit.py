import streamlit as st
import pandas as pd
from Kitsune import Kitsune
import matplotlib.pyplot as plt
import time
from scipy.stats import norm
import numpy as np
from io import BytesIO
import warnings

warnings.filterwarnings("ignore", category=RuntimeWarning)

st.title("Kitsune Network Anomaly Detection")

# Info box with brief description
st.info("""
Welcome to the Kitsune Network Anomaly Detection tool! Here you can upload network traffic files (PCAP, PCAPNG, or TSV) and analyze them for anomalies using the Kitsune algorithm. You can adjust parameters to fine-tune the analysis. Follow the steps below:

1. **Upload a File**: Choose a network traffic file to upload.
2. **Adjust Parameters**: Set the packet limit and grace periods to configure the analysis.
3. **Start Analysis**: Click 'Start with Config' to begin the anomaly detection process.

The results will be displayed as a plot, and you can download the generated image.
""")

# Add file uploader
uploaded_file = st.file_uploader("Choose a file (PCAP, PCAPNG, or TSV)", type=["pcap", "pcapng", "tsv"])

if uploaded_file:
    # Add adjustable widgets
    packet_limit = st.number_input("Packet Limit (default: 100000)", value=100000, step=5000, help='Set the maximum number of packets to process. Increasing this value may improve detection accuracy but also increases processing time.')
    
    col1, col2 = st.columns(2)
    with col1:
        FM_grace = st.number_input("FM Grace", value=5000, step=500, help='Learns normal network behavior from more packets. Increases accuracy, but also processing time and potential false positives.')
    with col2:
        AD_grace = st.number_input("AD Grace", value=50000, step=5000, help='Detects anomalies based on more packets. Increases accuracy, but also processing time and potential false negatives.')

    # Add start button
    start_button = st.button("Start with Config")

    if start_button:
        def main(packet_limit, FM_grace, AD_grace, uploaded_file):
            try:
                # Process the uploaded file with Kitsune
                file_path = uploaded_file.name
                K = Kitsune(file_path, packet_limit)
                st.write(f"Running Kitsune on {file_path}")

                RMSEs = []
                timestamps = []
                i = 0
                start_time = time.time()

                # Progress bar
                total_packets = packet_limit if packet_limit < float('inf') else None
                progress_bar = st.progress(0)

                packets_processed_text = st.text("Packets processed: 0")

                while True:
                    rmse = K.proc_next_packet()
                    if rmse == -1:
                        break
                    RMSEs.append(rmse)
                    timestamps.append(time.time() - start_time)
                    i += 1

                    # Update packets processed display every 1000 packets
                    if i % 1000 == 0:
                        packets_processed_text.text(f"Packets processed: {i}")

                    # Update progress bar
                    if total_packets is not None:
                        progress_bar.progress(i / total_packets)

                # Close the progress bar
                progress_bar.empty()

                st.success("Kitsune execution completed.")

                # Fit RMSE scores to a log-normal distribution
                benignSample = np.log(RMSEs[FM_grace + AD_grace + 1:100000])
                if np.std(benignSample) != 0:
                    logProbs = norm.logsf(np.log(RMSEs), np.mean(benignSample), np.std(benignSample))
                else:
                    logProbs = np.zeros_like(RMSEs)  # or some other default value

                # Plot the results
                fig, ax = plt.subplots(figsize=(10, 6))
                packet_numbers = range(FM_grace + AD_grace + 1, len(RMSEs))
                scatter = ax.scatter(packet_numbers, RMSEs[FM_grace + AD_grace + 1:], s=2, c=logProbs[FM_grace + AD_grace + 1:], cmap='RdYlGn')
                ax.set_yscale("log")
                ax.set_title("Anomaly Scores from Kitsune's Execution Phase", fontsize=16)
                ax.set_ylabel("RMSE (log scaled)", fontsize=14)
                ax.set_xlabel("Packet Number", fontsize=14)
                plt.colorbar(scatter, ax=ax, label='Log Probability', pad=0.15)
                plt.tight_layout()

                # Save the figure to a bytes object
                img_bytes = BytesIO()
                fig.savefig(img_bytes, format='png')
                img_bytes.seek(0)

                # Display the plot and add a download button
                st.pyplot(fig)
                st.download_button("Download Image", img_bytes, file_name="anomaly_scores.png", mime="image/png")

                # Info box explaining the generated image
                st.info("""
                The generated plot visualizes the anomaly scores of network packets processed by the Kitsune algorithm. Each point represents the RMSE (Root Mean Squared Error) of a packet, plotted on a logarithmic scale. The color of the points indicates the log probability of the RMSE scores, with different colors representing varying levels of anomaly likelihood. A lower RMSE suggests normal behavior, while a higher RMSE indicates potential anomalies. Use this plot to identify suspicious patterns and assess network security.
                """)

            except Exception as e:
                st.error(f"An error occurred: {e}")

        main(packet_limit, FM_grace, AD_grace, uploaded_file)
