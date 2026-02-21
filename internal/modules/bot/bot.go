package bot

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/db"
	"whispera/internal/modules/config"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

const (
	ModuleName    = "bot"
	ModuleVersion = "1.0.0"
)

type Bot struct {
	*base.Module
	config *config.BotConfig
	api    *tgbotapi.BotAPI
	db     *db.DB

	stopCh chan struct{}
	wg     sync.WaitGroup
}

func New(cfg interface{}, database *db.DB) (*Bot, error) {
	var conf *config.BotConfig
	if c, ok := cfg.(*config.BotConfig); ok {
		conf = c
	} else {
		conf = &config.BotConfig{}
	}

	b := &Bot{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: conf,
		db:     database,
		stopCh: make(chan struct{}),
	}

	return b, nil
}

func (b *Bot) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := b.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if conf, ok := cfg.(*config.BotConfig); ok {
		b.config = conf
	}

	if b.config.Token == "" {
		return fmt.Errorf("telegram token is required")
	}

	api, err := tgbotapi.NewBotAPI(b.config.Token)
	if err != nil {
		return fmt.Errorf("failed to init telegram bot: %w", err)
	}

	api.Debug = b.config.Debug
	b.api = api

	log.Printf("[BOT] Authorized on account %s", api.Self.UserName)
	return nil
}

func (b *Bot) Start() error {
	if err := b.Module.Start(); err != nil {
		return err
	}

	b.wg.Add(1)
	go b.updateLoop()

	go b.notifyStartup()

	b.SetHealthy(true, "bot running")
	return nil
}

func (b *Bot) notifyStartup() {
	time.Sleep(5 * time.Second)

	ip := base.GetPublicIP()
	if ip == "" {
		ip = "unknown"
	}

	msg := fmt.Sprintf("🚀 **Whispera Server Started**\n\n"+
		"🌍 IP: `%s`\n"+
		"📦 Version: `%s`\n"+
		"🕒 Time: `%s`",
		ip, ModuleVersion, time.Now().Format("2006-01-02 15:04:05"))

	b.Broadcast(msg)
}

func (b *Bot) Broadcast(msg string) {
	if b.config.AdminID != 0 {
		m := tgbotapi.NewMessage(b.config.AdminID, msg)
		m.ParseMode = "Markdown"
		b.api.Send(m)
	}

	for _, id := range b.config.MonitorAdminIDs {
		if id != 0 && id != b.config.AdminID {
			m := tgbotapi.NewMessage(id, msg)
			m.ParseMode = "Markdown"
			b.api.Send(m)
		}
	}
}

func (b *Bot) Stop() error {
	close(b.stopCh)
	b.wg.Wait()
	return b.Module.Stop()
}

func (b *Bot) updateLoop() {
	defer b.wg.Done()

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates := b.api.GetUpdatesChan(u)

	for {
		select {
		case <-b.stopCh:
			return
		case update, ok := <-updates:
			if !ok {
				return
			}
			if update.Message == nil {
				continue
			}

			b.handleMessage(update.Message)
		}
	}
}

func (b *Bot) handleMessage(msg *tgbotapi.Message) {
	if !msg.IsCommand() {
		return
	}

	cmd := msg.Command()

	switch cmd {
	case "start":
		b.handleStart(msg)
	case "me":
		b.handleMe(msg)
	case "id":
		reply := tgbotapi.NewMessage(msg.Chat.ID, fmt.Sprintf("Your Telegram ID: `%d`", msg.From.ID))
		reply.ParseMode = "Markdown"
		b.api.Send(reply)
	default:
		msg := tgbotapi.NewMessage(msg.Chat.ID, "I don't know that command")
		b.api.Send(msg)
	}
}

func (b *Bot) handleStart(msg *tgbotapi.Message) {
	txt := "👋 **Welcome to Whispera Bot!**\n\n" +
		"This bot helps you manage your VPN connection.\n" +
		"Commands:\n" +
		"/me - Show my profile and traffic\n" +
		"/id - Show my Telegram ID (for registration)"

	reply := tgbotapi.NewMessage(msg.Chat.ID, txt)
	reply.ParseMode = "Markdown"
	b.api.Send(reply)
}

func (b *Bot) handleMe(msg *tgbotapi.Message) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	user, err := b.db.GetUserByTelegramID(ctx, msg.From.ID)
	if err != nil {
		text := fmt.Sprintf("❌ You are not registered.\nAsk admin to link your Telegram ID: `%d`", msg.From.ID)
		reply := tgbotapi.NewMessage(msg.Chat.ID, text)
		reply.ParseMode = "Markdown"
		b.api.Send(reply)
		return
	}

	gbUsed := float64(user.TrafficUsed) / 1024 / 1024 / 1024
	gbLimit := float64(user.TrafficLimit) / 1024 / 1024 / 1024

	txt := fmt.Sprintf("👤 **Profile**: `%s`\n", user.Email)
	txt += fmt.Sprintf("📊 **Traffic**: %.2f GB / %.2f GB\n", gbUsed, gbLimit)

	if user.ValidUntil != nil {
		txt += fmt.Sprintf("⏳ **Expires**: %s\n", user.ValidUntil.Format("2006-01-02"))
	}

	reply := tgbotapi.NewMessage(msg.Chat.ID, txt)
	reply.ParseMode = "Markdown"
	b.api.Send(reply)
}

func Factory(cfg interface{}) (interfaces.Module, error) {
	return New(cfg, db.Global())
}
