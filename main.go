package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"

	_ "github.com/lib/pq" // pgx database/sql driver

	"time"
)

type SNMPCredential struct {
	Version   int    `json:"version"`
	Community string `json:"community,omitempty"`

	// SNMPv3 fields (omitempty so v1/v2c entries don't require them)
	User           string `json:"user,omitempty"`
	SecurityLevel  string `json:"securityLevel,omitempty"` // e.g., "noauth", "authnopriv", "authpriv"
	AuthProtocol   string `json:"authProtocol,omitempty"`  // e.g., "MD5", "SHA", "SHA256"
	AuthPassphrase string `json:"authPassphrase,omitempty"`
	PrivProtocol   string `json:"privProtocol,omitempty"` // e.g., "DES", "AES", "AES256"
	PrivPassphrase string `json:"privPassphrase,omitempty"`
}

type Config struct {
	db    *sql.DB
	lock  sync.Mutex
	start time.Time
}

var config Config

func get_snmp_config() {
	query, err := config.db.Query("select data from config where key_name = 'snmp_config';")
	if err != nil {
		log.Println("Error querying database: ", err)
		return
	}
	defer func(query *sql.Rows) {
		err := query.Close()
		if err != nil {
			log.Println("Error closing query: ", err)
			return
		}
	}(query)
	var data []byte
	for query.Next() {

		err := query.Scan(&data)
		if err != nil {
			log.Println("Error scanning data: ", err)
			continue
		}
		log.Println("Data: ", string(data))

	}
	var creds []SNMPCredential
	if err := json.Unmarshal(data, &creds); err != nil {
		log.Println(err)
	}
	fmt.Printf("parsed credentials %v\n", creds)
	for idx, cred := range creds {
		fmt.Printf("creds[%d] = %v\n", idx, cred)
	}

}

func timer() {

	dur := flag.Duration("d", 10*time.Second, "timer duration (e.g. 10s, 2m)")
	flag.Parse()

	if *dur <= 0 {
		fmt.Println("Please provide a positive duration, e.g. -d=10s")
		return
	}
	end := time.Now().Add(*dur)
	timer := time.NewTimer(*dur)
	ticker := time.NewTicker(1 * time.Second)
	defer func() {
		ticker.Stop()
		if !timer.Stop() {
			// Drain if it already fired
			select {
			case <-timer.C:
			default:
			}
		}
	}()

	// Handle Ctrl+C to cancel early
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)
	for {
		select {
		case <-ticker.C:
			get_snmp_config()
			remaining := time.Until(end)
			if remaining <= 0 {
				// Let the timer case handle final message
				continue
			}
			// Round to nearest second for display
			sec := (remaining + 500*time.Millisecond) / time.Second
			fmt.Printf("\rRemaining: %ds   ", sec)

		case <-timer.C:
			fmt.Print("\r") // clear the "Remaining" line
			fmt.Println("Time's up!")
			return
		case <-sigCh:
			fmt.Print("\r")
			fmt.Println("Timer canceled.")
			return
		}
	}
}

func main() {
	var err error
	connString := os.Getenv("PG_CONN_STRING")
	connString = fmt.Sprintf("%s?sslmode=disable", connString)
	log.Println("Connecting to database: ", connString)
	config.db, err = sql.Open("postgres", connString)
	if err != nil {
		panic(err)
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {
			panic(err)
		}
	}(config.db)
	// Duration flag, default 10s (supports 300ms, 2s, 1m, etc.)
	go timer()
	for {
		time.Sleep(1 * time.Second)
	}
}
