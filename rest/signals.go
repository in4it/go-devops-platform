package rest

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"
	"syscall"

	"github.com/in4it/go-devops-platform/users"
)

func handleSignals(c *Context) {
	// write pid file so other process can find it
	err := os.WriteFile(path.Join(c.AppDir, "rest-server.pid"), []byte(fmt.Sprintf("%d", os.Getpid())), 0664)
	if err != nil {
		log.Printf("Could not write pid file\n")
	}
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGHUP)
	for sig := range signalChannel {
		switch sig {
		case syscall.SIGHUP:
			c.ReloadConfig()
		}
	}
}

func (c *Context) ReloadConfig() {
	newC, err := NewContext(c.Storage.Client, c.ServerType, c.UserStore, c.SCIM.Client, c.LicenseUserCount, c.CloudType, c.Apps.Clients)
	if err != nil {
		log.Printf("ReloadConfig failed: %s\n", err)
		return
	}
	c.AppDir = newC.AppDir
	c.Hostname = newC.Hostname
	c.SetupCompleted = newC.SetupCompleted
	err = c.reloadUsers()
	if err != nil {
		log.Printf("ReloadConfig: could not reload users: %s\n", err)
		return
	}
	log.Printf("Config Reloaded!\n")
}

// reloadUsers re-reads the users from storage (e.g. after a password reset from
// the command line). The existing user store is updated in place, so every
// component that has a reference to it (and its hooks) keeps working.
func (c *Context) reloadUsers() error {
	reloaded, err := users.NewUserStore(c.Storage.Client, c.UserStore.GetMaxUsers())
	if err != nil {
		return fmt.Errorf("user store read error: %s", err)
	}
	users.UserStoreMu.Lock()
	defer users.UserStoreMu.Unlock()
	c.UserStore.Users = reloaded.Users
	return nil
}
