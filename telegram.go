package main

import "log"
import tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

func sendTelegramCommand(stringToSend string) {
	bot, _ := tgbotapi.NewBotAPI(runningConfig.TelegramBotToken)

	bot.Debug = true

	log.Printf("Authorized on account %s", bot.Self.UserName)
	for _, v := range runningConfig.TelegramChatIDs {
		msg := tgbotapi.NewMessage(v, stringToSend)
		bot.Send(msg)
	}

}
