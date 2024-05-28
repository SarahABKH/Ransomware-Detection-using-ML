import pefile

def extract_pe_features(filename):
    pe = pefile.PE(filename)

    features = {
        "Machine": pe.FILE_HEADER.Machine,
        "DebugSize": pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size,
        "DebugRVA": pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].VirtualAddress,
        "MajorImageVersion": pe.OPTIONAL_HEADER.MajorImageVersion,
        "MajorOSVersion": pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
        "ExportRVA": pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress,
        "ExportSize": pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size,
        "IatRVA": pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].VirtualAddress,
        "MajorLinkerVersion": pe.OPTIONAL_HEADER.MajorLinkerVersion,
        "MinorLinkerVersion": pe.OPTIONAL_HEADER.MinorLinkerVersion,
        "NumberOfSections": pe.FILE_HEADER.NumberOfSections,
        "SizeOfStackReserve": pe.OPTIONAL_HEADER.SizeOfStackReserve,
        "DllCharacteristics": pe.OPTIONAL_HEADER.DllCharacteristics,
        "ResourceSize": pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size,
        # Add more features as needed
    }

    # Close the PE file after use
    pe.close()

    return features

# Replace 'filename.exe' with the path to your executable file
filename = r"C:\Users\ASTECO J292\Downloads\Composer-Setup.exe"
features = extract_pe_features(filename)

# Print extracted features
for feature, value in features.items():
    print(f"{feature}: {value}")
