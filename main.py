import streamlit as st
from streamlit_option_menu import option_menu
import os

# Set the page configuration once at the start
st.set_page_config(page_title="Streamlit Navigation iForest", layout="centered")

# Get the absolute path of the current script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Define the folder paths for different sections using absolute paths
folder_paths = {
    "Kitsune": os.path.join(script_dir, "1.kitsune"),
    "iForest": os.path.join(script_dir, "2.iforest"),
    "Convert": os.path.join(script_dir, "3.convert"),
    "Visualize": os.path.join(script_dir, "4.visualize")
}

# Create a horizontal navigation menu
selected = option_menu(
    menu_title=None,  # Leave menu title as None for horizontal menu
    options=["Kitsune", "iForest", "Convert", "Visualize"],  # required
    icons=["graph-up", "tree", "repeat", "bar-chart"],  # optional
    menu_icon="cast",  # optional
    default_index=0,  # optional
    orientation="horizontal",  # Set the menu to horizontal
)

# Display content based on the selected menu
if selected == "Kitsune":
    
    # Change the working directory to the folder containing example_streamlit.py
    os.chdir(folder_paths["Kitsune"])
    exec(open("examplestreamlit.py").read())

elif selected == "iForest":
    
    # Change the working directory to the folder containing app.py
    os.chdir(folder_paths["iForest"])
    exec(open("app.py").read())

elif selected == "Convert":
    
    # Change the working directory to the folder containing convert.py
    os.chdir(folder_paths["Convert"])
    exec(open("convert.py").read())

elif selected == "Visualize":
    
    # Change the working directory to the folder containing visualize.py
    os.chdir(folder_paths["Visualize"])
    exec(open("visualize.py").read())
