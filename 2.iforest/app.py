import streamlit as st
import pandas as pd
import numpy as np
from sklearn.linear_model import SGDOneClassSVM
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.impute import SimpleImputer
from statsmodels.stats.outliers_influence import variance_inflation_factor
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler

# Function to calculate VIF
def calculate_vif(data):
    data = data.astype(float)
    data = data.replace([np.inf, -np.inf], np.nan)
    data = data.fillna(0)  # Alternatively, consider filling with mean or median
    vif_data = pd.DataFrame()
    vif_data["Feature"] = data.columns
    vif_data["VIF"] = [variance_inflation_factor(data.values, i) for i in range(data.shape[1])]
    return vif_data

# Function to detect anomalies using multiple methods
def detect_anomalies(data, nu, tol, contamination_if, contamination_lof, n_neighbors):
    scaler = StandardScaler()
    data_scaled = scaler.fit_transform(data)
    anomalies = pd.DataFrame(index=data.index)
    
    clf_sgd = SGDOneClassSVM(nu=nu, tol=tol).fit(data_scaled)
    anomalies['SGDOneClassSVM'] = clf_sgd.predict(data_scaled)
    
    clf_if = IsolationForest(contamination=contamination_if, random_state=0).fit(data_scaled)
    anomalies['IsolationForest'] = clf_if.predict(data_scaled)
    
    lof = LocalOutlierFactor(n_neighbors=n_neighbors, contamination=contamination_lof)
    anomalies['LocalOutlierFactor'] = lof.fit_predict(data_scaled)
    
    # Combine results by majority voting
    anomalies['Combined'] = anomalies.apply(lambda row: 1 if sum(row == -1) > 1 else -1, axis=1)
    
    return anomalies

# Streamlit App
st.title("Network Intrusion Detection Using Isolation Forest")
st.write("Upload your CSV file containing network packet information for anomaly detection.")

# Upload CSV file
uploaded_file = st.file_uploader("Choose a CSV file", type="csv")

if uploaded_file is not None:
    dt = pd.read_csv(uploaded_file)
    st.write("Data Preview:")
    st.write(dt.head())
    
    st.info("""
    - **sttl**: Source Time To Live, indicating the lifespan of a packet.
    - **swin**: Source Window Size, controlling data flow and congestion.
    - **stcpb**: Source TCP Base Sequence Number, managing packet order and retransmissions.
    - **dtcpb**: Destination TCP Base Sequence Number, ensuring packet reliability from the destination.
    """)

    # Data Cleaning and Initial Processing
    dt = dt.dropna(subset=['Time', 'Source', 'Destination', 'Protocol', 'Length'])
    dt['Length'] = pd.to_numeric(dt['Length'], errors='coerce')
    
    st.write("Set parameters for anomaly detection algorithms:")
    
    col1, col2 = st.columns(2)
    with col1:
        nu = st.number_input("SGDOneClassSVM 'nu'", min_value=0.01, max_value=0.75, value=0.6, step=0.05, 
                       help="SGDOneClassSVM 'nu' parameter controls the upper bound on the fraction of training errors and a lower bound of the fraction of support vectors.")
        tol = st.number_input("SGDOneClassSVM tolerance", min_value=1e-7, max_value=1e-2, value=1e-2, step=1e-6, 
                        help="SGDOneClassSVM 'tolerance' parameter determines the tolerance for the optimization. Smaller values lead to more accurate solutions but may take longer to compute.")
    
    with col2:
        contamination_if = st.number_input("Contamination for IsolationForest", min_value=0.01, max_value=0.75, value=0.5, step=0.1, 
                                  help="Contamination parameter for IsolationForest specifies the proportion of outliers in the data set.")
        contamination_lof = st.number_input("Contamination for LocalOutlierFactor", min_value=0.01, max_value=0.75, value=0.5, step=0.1, 
                                  help="Contamination parameter for LocalOutlierFactor specifies the proportion of outliers in the data set.")
        n_neighbors = st.number_input("LocalOutlierFactor n_neighbors", min_value=1, max_value=75, value=60, step=5, 
                                help="LocalOutlierFactor 'n_neighbors' parameter determines the number of neighbors to use for calculating the local density.")
    
    st.write("Performing anomaly detection...")
    
    # Loading button for anomaly detection
    if st.button("Detect Anomalies"):
        with st.spinner("Detecting anomalies..."):
            feature_columns = ['Length', 'sttl', 'swin', 'stcpb', 'dtcpb']  # Removed 'id'
            data_for_detection = dt[feature_columns].copy()
            
            # Convert relevant columns to numeric data types
            for column in feature_columns:
                data_for_detection.loc[:, column] = pd.to_numeric(data_for_detection[column], errors='coerce')
            
            # Impute missing values using mean imputation
            imputer = SimpleImputer(strategy='mean')
            imputed_data = imputer.fit_transform(data_for_detection)
            data_for_detection = pd.DataFrame(imputed_data, columns=feature_columns, index=data_for_detection.index)
            
            anomalies = detect_anomalies(data_for_detection, nu, tol, contamination_if, contamination_lof, n_neighbors)
            
            # Summarize anomalies
            dt['SGDOneClassSVM'] = anomalies['SGDOneClassSVM']
            dt['IsolationForest'] = anomalies['IsolationForest']
            dt['LocalOutlierFactor'] = anomalies['LocalOutlierFactor']
            dt['AnomalyScore'] = anomalies['Combined']
            dt['IsAnomalous'] = dt['AnomalyScore'] == -1
            
            # Provide feedback to the user
            anomaly_percentage = (dt['IsAnomalous'].sum() / len(dt)) * 100
            total_anomalies = dt['IsAnomalous'].sum()
            total_data_points = len(dt)
            
            if anomaly_percentage > 50:
                st.error(f"High Alert: {anomaly_percentage:.2f}% of the data points ({total_anomalies} out of {total_data_points}) are flagged as anomalous. The uploaded file requires immediate attention and further investigation.")
                st.write("Please review the anomalous data points and take necessary actions to mitigate any potential security risks.")
            elif 25 <= anomaly_percentage <= 50:
                st.warning(f"Moderate Alert: {anomaly_percentage:.2f}% of the data points ({total_anomalies} out of {total_data_points}) are flagged as anomalous. The uploaded file may contain suspicious activity.")
                st.write("It is recommended to analyze the anomalous data points and determine if any further actions are required.")
            elif 10 <= anomaly_percentage < 25:
                st.info(f"Low Alert: {anomaly_percentage:.2f}% of the data points ({total_anomalies} out of {total_data_points}) are flagged as anomalous. The uploaded file appears to have a moderate number of anomalies.")
                st.write("It is advisable to review the anomalous instances for any potential issues.")
            else:
                st.success("No Major Anomalies Detected: The uploaded file has less than 10% anomalous data points.")
                st.write("The file appears to be mostly clean and free from any major suspicious or abnormal activity.")
            
            # Visualize anomalies
            st.write("Anomalies detected:")
            st.write(dt[dt['IsAnomalous']].head())
    
    # Loading button for analysis
    if st.button("Generate Analysis"):
        with st.spinner("Generating analysis..."):
            if 'AnomalyScore' in dt.columns:
                # Plot distribution of the AnomalyScore
                plt.figure(figsize=(8, 6))
                sns.histplot(dt['AnomalyScore'], bins=20, kde=True, color='red')
                plt.title('Distribution of Anomaly Scores')
                plt.xlabel('Anomaly Score')
                plt.ylabel('Frequency')
                st.pyplot(plt)
                st.info("The distribution of anomaly scores provides insights into the range and frequency of anomaly scores assigned to the data points.")
            else:
                st.warning("Anomaly detection needs to be performed before generating the analysis. Please click the 'Detect Anomalies' button first.")
            
            # VIF Calculation
            num_var = dt.columns.drop(['No.', 'Info', 'Time', 'Source', 'Destination', 'Protocol'])
            vif_results = calculate_vif(dt[num_var])
            st.write("VIF Results:")
            st.write(vif_results)
            st.info("The Variance Inflation Factor (VIF) measures the multicollinearity among the independent variables in the dataset.")
            
            # Data Visualization
            st.write("Data Visualization:")
            
            # Plotting correlation heatmap of numerical variables
            plt.figure(figsize=(10, 8))
            sns.heatmap(dt[num_var].corr(), annot=True, cmap='coolwarm', fmt=".2f")
            plt.title('Correlation Heatmap')
            st.pyplot(plt)
            st.info("The correlation heatmap visualizes the pairwise correlations between the numerical variables in the dataset.")
            
            # Plotting scatter plots of selected features against the Length variable
            selected_features_to_plot = ['sttl', 'swin', 'stcpb', 'dtcpb']
            for feature in selected_features_to_plot:
                plt.figure(figsize=(6, 5))
                sns.scatterplot(x=dt[feature], y=dt['Length'], color='orange')
                plt.title(f'{feature} vs Length')
                plt.xlabel(feature)
                plt.ylabel('Length')
                st.pyplot(plt)
                st.info(f"The scatter plot displays the relationship between {feature} and the 'Length' variable.")
        
        st.success("Data analysis and visualization completed successfully!")
