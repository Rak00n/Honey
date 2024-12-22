# Honey
## Honeypot application for Windows and Linux with Telegram alerting

Requirements: 
  - libpcap (for Linux: "apt install libpcap-dev", for windows just install Wireshark)
  - Telegram Bot Token (you can create one with @BotFather)
  - Telegram Chat ID (after you created your bot send it any message and go to "https://api.telegram.org/bot<YOURTOKENSTRING>/getUpdates" and grab your chat id)

Before launch change all the necessary changes in **config.json**

Get help: **honey.exe -h**

Run the App: **honey.exe -config config.json**




