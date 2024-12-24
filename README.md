# Honey
## Honeypot application for Windows and Linux with Telegram alerting

Small application which listens network interface and reacts on incoming packets to specific local ports defined in configuration file.

This app doesn't open ports on your local machine, but this feature might arrive in future...

Simple configuration:
  - Network interface MAC address
  - Telegram Bot
  - Logging to local file

Requirements: 
  - libpcap (for Linux: "apt install libpcap-dev", for windows just install Wireshark)
  - Telegram Bot Token (you can create one with @BotFather)
  - Telegram Chat ID (after you created your bot send it any message and go to "https://api.telegram.org/botYOURTOKENSTRING/getUpdates" and grab your chat id)

Before launch change all the necessary changes in **config.json**

Get help: **honey.exe -h**

Run the App: **honey.exe -config config.json**




