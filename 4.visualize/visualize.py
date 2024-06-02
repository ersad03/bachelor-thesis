import streamlit as st
import dpkt
import socket
import pygeoip
import requests
from io import BytesIO
import folium
from folium import Marker
import streamlit.components.v1 as components

# Set Streamlit to wide mode
#st.set_page_config(layout="wide")

# Center the title
st.markdown("""
    <h1 style='text-align: center;'>PCAP to KML Converter and Visualizer</h1>
""", unsafe_allow_html=True)

# Add a shorter description
st.info("""
Upload a PCAP file to visualize network connections on a map:

1. **Upload**: Click "Choose a PCAP file" to upload.
2. **Process**: Click "Process PCAP" to visualize connections.
3. **Download**: Download the KML file for use in Google Earth.

Markers indicate the start (source IP) and end (destination IP) of each connection. Hover over lines for details.

**Note**: Ensure your PCAP file contains valid network traffic data.
""")

# Load the GeoIP database
gi = pygeoip.GeoIP('GeoLiteCity.dat')

def get_external_ip():
    try:
        response = requests.get('https://api.ipify.org')
        return response.text
    except requests.RequestException:
        return None

def get_geolocation(ip):
    try:
        record = gi.record_by_name(ip)
        return record['latitude'], record['longitude']
    except:
        return 0, 0

def plotIPs(pcap, external_ip):
    kmlPts = ''
    seen_ips = set()
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            if (src, dst) not in seen_ips:
                seen_ips.add((src, dst))
                KML, line_coords, tooltip_text = retKML(dst, src, external_ip)
                kmlPts += KML
                # Plot the line on the map with a tooltip and prettier style
                if line_coords:
                    folium.PolyLine(
                        line_coords, 
                        color='blue', 
                        weight=3, 
                        opacity=0.7, 
                        tooltip=tooltip_text
                    ).add_to(mymap)
                    # Add markers at the start and end of the line
                    Marker(line_coords[0], popup=f"Start: {src}").add_to(mymap)
                    Marker(line_coords[-1], popup=f"End: {dst}").add_to(mymap)
        except:
            pass
    return kmlPts

def retKML(dstip, srcip, external_ip):
    dst = gi.record_by_name(dstip)
    src = gi.record_by_name(external_ip) if external_ip else None
    try:
        dstlongitude = dst['longitude']
        dstlatitude = dst['latitude']
        srclongitude = src['longitude'] if src else 0
        srclatitude = src['latitude'] if src else 0
        kml = (
            '<Placemark>\n'
            '<name>%s</name>\n'
            '<extrude>1</extrude>\n'
            '<tessellate>1</tessellate>\n'
            '<styleUrl>#transBluePoly</styleUrl>\n'
            '<LineString>\n'
            '<coordinates>%6f,%6f\n%6f,%6f</coordinates>\n'
            '</LineString>\n'
            '</Placemark>\n'
        ) % (dstip, dstlongitude, dstlatitude, srclongitude, srclatitude)
        # Create Bezier curve points
        mid_lat = (srclatitude + dstlatitude) / 2
        mid_lon = (srclongitude + dstlongitude) / 2
        control_lat1 = mid_lat + 0.5  # Adjust curvature
        control_lon1 = mid_lon - 0.5  # Adjust curvature
        control_lat2 = mid_lat - 0.5  # Adjust curvature
        control_lon2 = mid_lon + 0.5  # Adjust curvature
        line_coords = [(srclatitude, srclongitude), (control_lat1, control_lon1), (control_lat2, control_lon2), (dstlatitude, dstlongitude)]
        tooltip_text = f"From: {srcip} To: {dstip}"
        return kml, line_coords, tooltip_text
    except:
        return '', None, ''

uploaded_file = st.file_uploader("Choose a PCAP file", type="pcap")
if uploaded_file is not None:
    if st.button('Process PCAP'):
        f = BytesIO(uploaded_file.getvalue())
        pcap = dpkt.pcap.Reader(f)
        external_ip = get_external_ip()
        
        # Get the geolocation of the external IP
        center_lat, center_lon = get_geolocation(external_ip)
        
        # Initialize the map centered at the external IP location
        mymap = folium.Map(location=[center_lat, center_lon], zoom_start=4)

        kmlheader = '<?xml version="1.0" encoding="UTF-8"?>\n<kml xmlns="http://www.opengis.net/kml/2.2">\n<Document>\n' \
                    '<Style id="transBluePoly">' \
                    '<LineStyle>' \
                    '<width>1.5</width>' \
                    '<color>501400E6</color>' \
                    '</LineStyle>' \
                    '</Style>'
        kmlfooter = '</Document>\n</kml>\n'
        kmldoc = kmlheader + plotIPs(pcap, external_ip) + kmlfooter

        # Save to a buffer
        kml_buffer = BytesIO()
        kml_buffer.write(kmldoc.encode())
        kml_buffer.seek(0)

        st.download_button(
            label="Download KML File",
            data=kml_buffer,
            file_name="output.kml",
            mime="application/vnd.google-earth.kml+xml"
        )
        
        # Save the map to an HTML file
        map_html = mymap._repr_html_()

        # Display the map in Streamlit
        map_html = f"""
        <style>
        .map {{
            width: 100%;
            height: 100vh;
        }}
        </style>
        <div class="map">{map_html}</div>
        """

        components.html(map_html, height=800)
