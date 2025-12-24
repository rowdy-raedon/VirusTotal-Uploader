# VirusTotal File Checker

A Python PyQt5 application that allows you to upload files to VirusTotal for malware scanning and analysis.

## Features

- **Easy File Upload**: Select any file from your system and upload it to VirusTotal
- **Real-time Status Updates**: See the progress of your file upload and analysis
- **Detailed Scan Results**: View comprehensive scan results including:
  - File hashes (MD5, SHA1, SHA256)
  - Scan statistics from multiple antivirus engines
  - Detailed threat detection results
  - Overall threat verdict
- **API Key Management**: Securely store your API key (saved locally in config.json)
- **Modern UI**: Clean and intuitive user interface built with PyQt5

## Requirements

- Python 3.7 or higher
- VirusTotal API key (free tier available)

## Installation

1. **Clone or download this repository**

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Get a VirusTotal API key**:
   - Visit https://www.virustotal.com/gui/join-us
   - Sign up for a free account
   - Go to your profile settings to get your API key

## Usage

### Option 1: Run as Python Script
```bash
python virus_total_checker.py
```

### Option 2: Build Executable (.exe)

**Windows:**
1. Run the build script:
   ```bash
   python build_exe.py
   ```
   Or double-click `build_exe.bat`

2. Find the executable in the `dist` folder:
   - `dist\VirusTotalChecker.exe`

3. You can distribute this .exe file to other Windows users (no Python installation required!)

**Note:** The executable will be standalone and includes all dependencies.

2. **Enter your API key**:
   - Paste your VirusTotal API key in the "API Key" field
   - The key will be saved automatically for future use

3. **Select a file**:
   - Click "Select File" to choose the file you want to scan
   - Supported: Any file type (VirusTotal free API has a 32MB file size limit)

4. **Upload and scan**:
   - Click "Upload & Scan File"
   - Wait for the analysis to complete (usually takes 10-60 seconds)
   - View the detailed scan results in the results panel

## File Size Limits

- **Free API**: 32MB maximum file size
- **Premium API**: 200MB maximum file size

## API Rate Limits

VirusTotal free API has rate limits:
- 4 requests per minute
- 500 requests per day

## Security Note

Your API key is stored locally in `config.json` in the same directory as the application. Keep this file secure and do not share it.

## Troubleshooting

- **"Upload failed"**: Check your API key and internet connection
- **"Analysis timeout"**: The file may be taking longer to analyze. Try again later
- **"File not found"**: Make sure the file path is correct and the file exists

## License

This project is provided as-is for educational and personal use.

