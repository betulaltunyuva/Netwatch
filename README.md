# NetWatch - Local Network Monitoring Dashboard

## Overview
NetWatch is a local network monitoring dashboard prototype built with Python and Flask.  
It is designed to observe and analyze network traffic in a simple web interface.  
The project can capture live network packets with Scapy and summarize recent traffic in the dashboard.  
If live capture is unavailable due to missing dependencies or system limitations, it can fall back to sample data.  
The dashboard is not a streaming real-time monitor, but it presents up-to-date summaries from recent packet capture windows.

## Features
- Live packet capture support
- Automatic fallback to sample data
- Real traffic summary
- Alerts
- Top source IPs
- Top destination ports
- Recent packets
- Protocol filtering
- Protocol distribution chart
- Last updated badge
- Dark dashboard UI

## Technologies Used
- Python
- Flask
- HTML
- CSS
- JavaScript

## Project Structure
```text
app.py
sniffer.py
detector.py
logger.py
templates/
static/
logs/
requirements.txt
README.md
```

## How to Run
1. Create a virtual environment.
2. Activate the virtual environment.
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the application:
   ```bash
   python app.py
   ```
5. Open your browser and go to:
   [http://127.0.0.1:5000](http://127.0.0.1:5000)

## Notes
- Live packet capture uses Scapy and may require administrator/root privileges depending on your OS.
- On Windows, Npcap may be required for packet capture support.
- If live capture cannot run, the app can use sample data as a fallback mode.
- Intended for educational and portfolio purposes.

## Future Improvements
- Real-time packet capture
- Export logs
- Advanced suspicious traffic detection
- Search and filtering
- Charts and analytics improvements

## Author

