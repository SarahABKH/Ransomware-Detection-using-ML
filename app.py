from flask import Flask, render_template, request
import os
import pefile
import joblib
import pandas as pd
import re  # Import regular expression module

# Define feature extraction function
def extract_pe_features(filename):
    pe = pefile.PE(filename)
    features = {
        "Machine": pe.FILE_HEADER.Machine ,
        "DebugSize": pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size,
        "DebugRVA": pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].VirtualAddress,
        "MajorImageVersion": pe.OPTIONAL_HEADER.MajorImageVersion,
        "MajorOSVersion": pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
        "ExportRVA": pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress,
        "ExportSize": pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size,
        "IatVRA": pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].VirtualAddress,
        "MajorLinkerVersion": pe.OPTIONAL_HEADER.MajorLinkerVersion,
        "MinorLinkerVersion": pe.OPTIONAL_HEADER.MinorLinkerVersion,
        "NumberOfSections": pe.FILE_HEADER.NumberOfSections,
        "SizeOfStackReserve": pe.OPTIONAL_HEADER.SizeOfStackReserve,
        "DllCharacteristics": pe.OPTIONAL_HEADER.DllCharacteristics,
        "ResourceSize": pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size,
        # Add more features as needed
    }
    print("features extracted:")
    print(features)
    # Extract Bitcoin addresses
    bitcoin_addresses = extract_bitcoin_addresses_from_file(filename)
    features['BitcoinAddresses'] = bitcoin_addresses
    
    pe.close()
    return features

# Define function to extract Bitcoin addresses from a file
def extract_bitcoin_addresses_from_file(filename):
    bitcoin_addresses = []
    with open(filename, 'rb') as f:
        content = f.read().decode('utf-8', errors='ignore')  # Decode binary content to text
        
        # Regular expression pattern to match Bitcoin addresses
        bitcoin_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
        
        # Search for Bitcoin addresses in the file content
        bitcoin_matches = re.findall(bitcoin_pattern, content)
        
        # Add unique Bitcoin addresses to the list
        bitcoin_addresses.extend(set(bitcoin_matches))
    
    return bitcoin_addresses

# Define classification function
import pandas as pd
from sklearn.preprocessing import OneHotEncoder
def classify(features):
    # Load the model files
    import joblib
    import pandas as pd

    print("Loading model files...")
    random_forest_model = joblib.load("random_forest_model.pkl")
    xgboost_model = joblib.load("xgboost_model.pkl")
    print("Model files loaded.")

    # Encode BitcoinAddresses using one-hot encoding
    print("Encoding BitcoinAddresses...")
    bitcoin_addresses_encoded = [[False, True]]  # Directly creating False and True values
    print("BitcoinAddresses encoded.")
    
    # Get feature names after encoding
    bitcoin_addresses_columns = ['BitcoinAddresses_0', 'BitcoinAddresses_1']

    # Initialize encoded BitcoinAddresses DataFrame with default values
    bitcoin_addresses_df = pd.DataFrame(bitcoin_addresses_encoded, columns=bitcoin_addresses_columns)
    

    # Check for MajorOSVersion and encode accordingly
    print("Encoding MajorOSVersion...")
    major_os_version_columns = [f'MajorOSVersion_{i}' for i in [6, 5, 10, 4, 13, 8, 9, 1, 7]]
    major_os_version_df = pd.DataFrame(columns=major_os_version_columns)
    major_os_version_df.loc[0, f'MajorOSVersion_{features["MajorOSVersion"]}'] = True
    major_os_version_df = major_os_version_df.fillna(False)  # Fill NaN values with False
    print("MajorOSVersion encoded.")
    print(major_os_version_df)

    # Check for Machine value and encode accordingly
    print("Encoding Machine...")
    machine_columns = ['Machine_34404', 'Machine_332']
    machine_df = pd.DataFrame(columns=machine_columns)
    machine_df.loc[0, f'Machine_{features["Machine"]}'] = True
    machine_df = machine_df.fillna(False)  # Fill NaN values with False
    print("Machine encoded.")
    print(machine_df)

    print("Features")
    print(features)
    # Convert the features dictionary to a DataFrame
    print("Converting features dictionary to DataFrame...")
    features_df = pd.DataFrame([features])
    print("Features DataFrame created.")
    print(features_df)

    # Concatenate the encoded features
    print("Concatenating encoded features...")
    features_df = pd.concat([features_df.drop(['BitcoinAddresses', 'MajorOSVersion', 'Machine'], axis=1),
                             bitcoin_addresses_df, major_os_version_df, machine_df], axis=1)
    print("Encoded features concatenated.")
    print(features_df)
    print("Bitcoing Address",bitcoin_addresses_df)

    # Reorder columns according to the desired sequence
    desired_features_order = [
        'DllCharacteristics',
        'DebugSize',
        'MajorLinkerVersion',
        'DebugRVA',
        'ResourceSize',
        'Machine_34404',
        'SizeOfStackReserve',
        'Machine_332',
        'NumberOfSections',
        'IatVRA',  # Changed from 'IatRVA'
        'MajorImageVersion',
        'MajorOSVersion_6',
        'MajorOSVersion_5',
        'ExportSize',
        'MajorOSVersion_10',
        'MinorLinkerVersion',
        'ExportRVA',
        'MajorOSVersion_4',
        'BitcoinAddresses_1',
        'BitcoinAddresses_0',
        'MajorOSVersion_13',
        'MajorOSVersion_8',
        'MajorOSVersion_9',
        'MajorOSVersion_1',
        'MajorOSVersion_7'
    ]

    # Reorder the columns
    print("Reordering columns...")
    features_df = features_df[desired_features_order]
    print("Columns reordered.")
    print(features_df)

    # Use models for classification
    print("Predicting with Random Forest model...")
    random_forest_prediction = random_forest_model.predict(features_df)
    print("Prediction with Random Forest model complete.")
    print(random_forest_prediction)
    # print("Predicting with XGBoost model...")
    # xgboost_prediction = xgboost_model.predict(features_df)
    # print("Prediction with XGBoost model complete.")

    # Combine predictions (example)
    if random_forest_prediction == 1:
        return render_template('ransomware.html')
    else:
        return render_template('goodware.html')


# Define Flask app
app = Flask(__name__)

# Define the upload folder
UPLOAD_FOLDER = 'content/saved_files'

# Create the directory for saving uploaded files if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Define routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part'
    file = request.files['file']
    if file.filename == '':
        return 'No selected file'
    # Save the uploaded file
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)
    # Extract features
    features = extract_pe_features(file_path)
    
    # Print extracted features
    print("Extracted Features:")
    for key, value in features.items():
        print(f"{key}: {value}")

    # Classify features
    classification_result = classify(features)
    return classification_result

# Run Flask app
if __name__ == '__main__':
    app.debug = True
    app.run(host='localhost', port=9874)
