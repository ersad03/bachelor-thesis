from Kitsune import Kitsune
import numpy as np
import time
import sys
from tkinter import filedialog
import tkinter as tk
from scipy.stats import norm
from matplotlib import pyplot as plt
from matplotlib import cm

# File location
root = tk.Tk()
root.withdraw()
path = filedialog.askopenfilename()

# Check if the file is a valid pcap or tsv file
if not (path.endswith('.pcap') or path.endswith('.pcapng') or path.endswith('.tsv')):
    print("Error: The file must be a pcap, pcapng, or tsv file")
    sys.exit(1)

packet_limit = np.Inf  # the number of packets to process

# KitNET params:
maxAE = 10  # maximum size for any autoencoder in the ensemble layer
FMgrace = 5000  # the number of instances taken to learn the feature mapping (the ensemble's architecture)
ADgrace = 50000  # the number of instances used to train the anomaly detector (ensemble itself)

# Build Kitsune
K = Kitsune(path, packet_limit, maxAE, FMgrace, ADgrace)

print("Running Kitsune:")
RMSEs = []
i = 0
start = time.time()
# Here we process (train/execute) each individual packet.
# In this way, each observation is discarded after performing process() method.
while True:
    i += 1
    if i % 1000 == 0:
        print(i)
    rmse = K.proc_next_packet()
    if rmse == -1:
        break
    RMSEs.append(rmse)
stop = time.time()
print("Complete. Time elapsed: " + str(stop - start))

# Here we demonstrate how one can fit the RMSE scores to a log-normal distribution (useful for finding/setting a cutoff threshold \phi)
benignSample = np.log(RMSEs[FMgrace + ADgrace + 1:100000])
logProbs = norm.logsf(np.log(RMSEs), np.mean(benignSample), np.std(benignSample))

# plot the RMSE anomaly scores
print("Plotting results")
plt.figure(figsize=(10, 5))
fig = plt.scatter(range(FMgrace + ADgrace + 1, len(RMSEs)), RMSEs[FMgrace + ADgrace + 1:], s=0.1, c=logProbs[FMgrace + ADgrace + 1:],cmap='RdYlGn')
plt.yscale("log")
plt.title("Anomaly Scores from Kitsune's Execution Phase")
plt.ylabel("RMSE (log scaled)")
plt.xlabel("Time elapsed [min]")
figbar = plt.colorbar()
figbar.ax.set_ylabel('Log Probability\n ', rotation=270)
plt.show()