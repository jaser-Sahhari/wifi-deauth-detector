# WiFi Deauthentication Attack Detector

![banner](https://img.shields.io/badge/status-active-brightgreen)

A lightweight Python tool for detecting Wi-Fi deauthentication (Deauth) attacks in real-time on Linux systems using Scapy.

## ⚙️ Features

- Real-time detection of Deauth frames.
- Terminal-based interactive dashboard using [rich](https://github.com/Textualize/rich).
- Automatically enables monitor mode using `airmon-ng`.
- No need for external databases or complex setup.

## 🧰 Requirements

- Python 3.7+
- Aircrack-ng tools
- Scapy
- rich

Install requirements:
```bash
sudo apt update && sudo apt install aircrack-ng
pip3 install -r requirements.txt
```

## 📦 Included Files

| File                 | Description                                      |
|----------------------|--------------------------------------------------|
| `deauth_detector.py` | Main detection script                           |
| `requirements.txt`   | Required Python libraries                        |
| `README.md`          | This file – user guide                          |
| `deauth_detector.log`| Automatically generated log file during runtime |

## ▶️ How to Run

```bash
sudo python3 deauth_detector.py
```

## 🛑 To Stop
- Press `Ctrl + C` to terminate.
- The script automatically restores the interface to normal mode.

## ⚠️ Notes

- Make sure your Wi-Fi card supports monitor mode.
- You may need to stop services like `NetworkManager` while capturing.

## 📜 License

MIT License

## 👨‍💻 Author

Open-source project built for learning and practical use.

> If you find this tool useful, consider leaving a ⭐ on GitHub!

