package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"

	"github.com/gosnmp/gosnmp"
	_ "github.com/lib/pq" // pgx database/sql driver

	"time"
)

type ExporterSNMPData struct {
	SysDescr    string `json:"sysDescr"`
	SysUptime   string `json:"sysUptime"`
	SysName     string `json:"sysName"`
	SysContact  string `json:"sysContact"`
	SysLocation string `json:"sysLocation"`
	SysObjectID string `json:"sysObjectID"`
	SysServices string `json:"sysServices"`
}
type Interface struct {
	ID          int64     `db:"id" json:"id"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
	Exporter    int64     `db:"exporter" json:"exporter"`
	SNMPIndex   int64     `db:"snmp_index" json:"snmp_index"`
	Description *string   `db:"description" json:"description,omitempty"`
	Alias       *string   `db:"alias" json:"alias,omitempty"`
	Speed       *string   `db:"speed" json:"speed,omitempty"`
	Enabled     *bool     `db:"enabled" json:"enabled,omitempty"`
}

type Exporter struct {
	ID              int64     `db:"id" json:"id"`
	CreatedAt       time.Time `db:"created_at" json:"created_at"`
	IPBin           int32     `db:"ip_bin" json:"ip_bin"`
	IPInet          string    `db:"ip_inet" json:"ip_inet"`
	Name            string    `db:"name" json:"name"`
	SNMPVersion     *int16    `db:"snmp_version" json:"snmp_version,omitempty"`
	SNMPCommunity   *string   `db:"snmp_community" json:"snmp_community,omitempty"`
	SNMPv3Username  *string   `db:"snmpv3_username" json:"snmpv3_username,omitempty"`
	SNMPv3Level     *string   `db:"snmpv3_level" json:"snmpv3_level,omitempty"`
	SNMPv3AuthProto *string   `db:"snmpv3_auth_proto" json:"snmpv3_auth_proto,omitempty"`
	SNMPv3AuthPass  *string   `db:"snmpv3_auth_pass" json:"snmpv3_auth_pass,omitempty"`
	SNMPv3PrivProto *string   `db:"snmpv3_priv_proto" json:"snmpv3_priv_proto,omitempty"`
	SNMPv3PrivPass  *string   `db:"snmpv3_priv_pass" json:"snmpv3_priv_pass,omitempty"`
}

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
	db         *sql.DB
	mutex      sync.Mutex
	exporters  []Exporter
	interfaces []Interface
	snmp       []SNMPCredential
	start      time.Time
	wg         sync.WaitGroup
	chExit     chan bool
}

const (
	SysUptime = ".1.3.6.1.2.1.1.3.0"
	SysDescr  = ".1.3.6.1.2.1.1.1.0"
	ifDescr   = ".1.3.6.1.2.1.2.2.1.2."
	ifName    = ".1.3.6.1.2.1.31.1.1.1.1."
	ifAlias   = ".1.3.6.1.2.1.31.1.1.1.18."
)

var config Config

func saveSNMPCredentials(e Exporter, idx int, name string) (bool, error) {
	cred := config.snmp[idx]
	exporterId := e.ID
	var err error
	var _ sql.Result
	if cred.Version == 1 || cred.Version == 2 {
		_, err = config.db.Exec("UPDATE exporters SET snmp_version = $1, snmp_community = $2, name = $3 WHERE id = $4;", cred.Version, cred.Community, name, exporterId)
	} else if cred.Version == 3 {
		_, err = config.db.Exec("update exporters set snmp_version = 3, snmpv3_username = $1, snmpv3_level = $2, snmpv3_auth_proto = $3, snmpv3_auth_pass = $4,snmpv3_priv_proto = $5 , snmpv3_priv_pass = $6, name = $7 where id = $8",
			cred.User, cred.SecurityLevel, cred.AuthProtocol, cred.AuthPassphrase, cred.PrivProtocol, cred.PrivPassphrase, name, exporterId)
	} else {
		err = fmt.Errorf("invalid version")

	}
	if err != nil {
		return false, err
	}
	return true, nil

}

func detectSNMPCredentials(e Exporter) (int, error) {
	var g *gosnmp.GoSNMP
	var name string
	var oids []string
	oids = append(oids, SysDescr)
	for idx, cred := range config.snmp {
		name = ""
		log.Printf("Exporter: %s SNMP credential %d: %v\n", e.IPInet, idx, cred)
		if cred.Version == 1 || cred.Version == 2 {
			var version gosnmp.SnmpVersion
			switch cred.Version {
			case 1:
				version = gosnmp.Version1
			case 2:
				version = gosnmp.Version2c
			}
			g = &gosnmp.GoSNMP{
				Target:    e.IPInet,
				Port:      161,
				Version:   version,
				Timeout:   5 * time.Second,
				Retries:   5,
				Community: cred.Community,
			}
			if err := g.Connect(); err != nil {
				continue
			}
			defer func(Conn net.Conn) {
				err := Conn.Close()
				if err != nil {
					log.Println("Error closing connection: ", err)
				}
			}(g.Conn)

			pkt, err := g.Get(oids)
			if err != nil {
				continue
			}
			if pkt == nil || pkt.Error != gosnmp.NoError {
				continue
			}

			for _, pdu := range pkt.Variables {

				fmt.Printf("%s = %v\n", pdu.Name, pdu.Value)
				log.Printf("%s = %s\n", pdu.Name, string(pdu.Value.([]byte)))
				name = string(pdu.Value.([]byte))
			}
			credentials, err := saveSNMPCredentials(e, idx, name)
			if err != nil {
				log.Println("Could not save credentials: ", err)
			}
			if credentials {
				log.Println("Credentials saved")
			}
			return idx, nil

		} else if cred.Version == 3 {
			var ap gosnmp.SnmpV3MsgFlags
			var authprot gosnmp.SnmpV3AuthProtocol
			var privprot gosnmp.SnmpV3PrivProtocol
			sl := strings.ToLower(cred.SecurityLevel)
			switch sl {
			case "noauthnopriv":
				ap = gosnmp.NoAuthNoPriv
			case "authnopriv":
				ap = gosnmp.AuthNoPriv
			case "authpriv":
				ap = gosnmp.AuthPriv
			}
			capr := strings.ToUpper(cred.AuthProtocol)
			switch capr {
			case "MD5":
				authprot = gosnmp.MD5
			case "SHA":
				authprot = gosnmp.SHA
			}
			pvr := strings.ToUpper(cred.PrivProtocol)
			switch pvr {
			case "DES":
				privprot = gosnmp.DES
			case "AES":
				privprot = gosnmp.AES
			}
			g = &gosnmp.GoSNMP{
				Target:        e.IPInet,
				Port:          161,
				Version:       gosnmp.Version3,
				Timeout:       5 * time.Second,
				Retries:       5,
				SecurityModel: gosnmp.UserSecurityModel,
				MsgFlags:      ap, // or gosnmp.NoAuthNoPriv / gosnmp.AuthNoPriv
				SecurityParameters: &gosnmp.UsmSecurityParameters{
					UserName:                 cred.User,
					AuthenticationProtocol:   authprot, // or gosnmp.MD5, SHA224/256 if supported
					AuthenticationPassphrase: cred.AuthPassphrase,
					PrivacyProtocol:          privprot, // or gosnmp.DES, AES192/256* if supported
					PrivacyPassphrase:        cred.PrivPassphrase,
				},
			}
			if err := g.Connect(); err != nil {
				continue
			}
			defer func(Conn net.Conn) {
				err := Conn.Close()
				if err != nil {
					log.Println("Error closing connection: ", err)
				}
			}(g.Conn)

			pkt, err := g.Get(oids)
			if err != nil {
				continue
			}
			if pkt == nil || pkt.Error != gosnmp.NoError {
				continue
			}
			for _, pdu := range pkt.Variables {
				fmt.Printf("%s = %v\n", pdu.Name, pdu.Value)
				log.Printf("%s = %s\n", pdu.Name, string(pdu.Value.([]byte)))
				name = string(pdu.Value.([]byte))
			}
			credentials, err := saveSNMPCredentials(e, idx, name)
			if err != nil {
				log.Println("Could not save credentials: ", err)
			}
			if credentials {
				log.Println("Credentials saved")
			}
			return idx, nil

		}

	}

	return -1, fmt.Errorf("not matching creds")

}

func pollInterface(e *Exporter, i *Interface, wg *sync.WaitGroup) {
	defer wg.Done()
	var g *gosnmp.GoSNMP
	var oids []string
	ifDescrOID := ifDescr + "." + fmt.Sprintf("%d", i.SNMPIndex)
	oids = append(oids, ifDescrOID)
	ifAliasOID := ifAlias + "." + fmt.Sprintf("%d", i.SNMPIndex)
	oids = append(oids, ifAliasOID)
	log.Println("Exporter: ", e, " Interface: ", i)
	log.Println("OIDs: ", oids)
	if *e.SNMPVersion == 1 || *e.SNMPVersion == 2 {
		var version gosnmp.SnmpVersion
		switch *e.SNMPVersion {
		case 1:
			version = gosnmp.Version1
		case 2:
			version = gosnmp.Version2c
		}
		g = &gosnmp.GoSNMP{
			Target:    e.IPInet,
			Port:      161,
			Version:   version,
			Timeout:   5 * time.Second,
			Retries:   5,
			Community: *e.SNMPCommunity,
		}
		if err := g.Connect(); err != nil {
			log.Println("Error connecting to exporter: ", err)
			return
		}
		defer func(Conn net.Conn) {
			err := Conn.Close()
			if err != nil {
				log.Println("Error closing connection: ", err)
			}
		}(g.Conn)

		pkt, err := g.Get(oids)
		if err != nil {
			return
		}
		if pkt == nil || pkt.Error != gosnmp.NoError {
			log.Println("Error getting data: ", err)
			return
		}
		for idx, pdu := range pkt.Variables {
			fmt.Printf("%s = %v\n", pdu.Name, pdu.Value)
			log.Printf("%s = %s\n", pdu.Name, string(pdu.Value.([]byte)))
			val := fmt.Sprintf("%s", string(pdu.Value.([]byte)))
			switch idx {
			case 0:
				i.Description = &val
			case 1:
				i.Alias = &val

			}
		}

	} else if *e.SNMPVersion == 3 {
		var ap gosnmp.SnmpV3MsgFlags
		var authprot gosnmp.SnmpV3AuthProtocol
		var privprot gosnmp.SnmpV3PrivProtocol
		sl := strings.ToLower(*e.SNMPv3Level)
		switch sl {
		case "noauthnopriv":
			ap = gosnmp.NoAuthNoPriv
		case "authnopriv":
			ap = gosnmp.AuthNoPriv
		case "authpriv":
			ap = gosnmp.AuthPriv
		}
		capr := strings.ToUpper(*e.SNMPv3AuthProto)
		switch capr {
		case "MD5":
			authprot = gosnmp.MD5
		case "SHA":
			authprot = gosnmp.SHA
		}
		pvr := strings.ToUpper(*e.SNMPv3PrivProto)
		switch pvr {
		case "DES":
			privprot = gosnmp.DES
		case "AES":
			privprot = gosnmp.AES
		}
		g = &gosnmp.GoSNMP{
			Target:        e.IPInet,
			Port:          161,
			Version:       gosnmp.Version3,
			Timeout:       5 * time.Second,
			Retries:       5,
			SecurityModel: gosnmp.UserSecurityModel,
			MsgFlags:      ap, // or gosnmp.NoAuthNoPriv / gosnmp.AuthNoPriv
			SecurityParameters: &gosnmp.UsmSecurityParameters{
				UserName:                 *e.SNMPv3Username,
				AuthenticationProtocol:   authprot, // or gosnmp.MD5, SHA224/256 if supported
				AuthenticationPassphrase: *e.SNMPv3AuthPass,
				PrivacyProtocol:          privprot, // or gosnmp.DES, AES192/256* if supported
				PrivacyPassphrase:        *e.SNMPv3PrivPass,
			},
		}
		if err := g.Connect(); err != nil {
			log.Println("Error connecting to exporter: ", err)
			return
		}
		defer func(Conn net.Conn) {
			err := Conn.Close()
			if err != nil {
				log.Println("Error closing connection: ", err)
			}
		}(g.Conn)

		pkt, err := g.Get(oids)
		if err != nil {
			log.Println("Error getting data: ", err)
			return
		}
		if pkt == nil || pkt.Error != gosnmp.NoError {
			log.Println("Error getting data: ", err)
			return
		}
		for idx, pdu := range pkt.Variables {
			fmt.Printf("%s = %v\n", pdu.Name, pdu.Value)
			log.Printf("%s = %s\n", pdu.Name, string(pdu.Value.([]byte)))
			val := fmt.Sprintf("%s", string(pdu.Value.([]byte)))
			switch idx {
			case 0:
				i.Description = &val
			case 1:
				i.Alias = &val

			}
		}

	}

}

func getInterfaces() ([]Interface, error) {
	query, err := config.db.Query("SELECT\n  id, created_at, exporter, snmp_index, description, alias,speed,enabled   FROM interfaces;")
	if err != nil {
		log.Println("Error querying database: ", err)
		return nil, err
	}
	defer func(query *sql.Rows) {
		err := query.Close()
		if err != nil {
			log.Println("Error closing query: ", err)
			return
		}
	}(query)

	var interfaces []Interface
	for query.Next() {
		var i Interface
		err := query.Scan(
			&i.ID,
			&i.CreatedAt,
			&i.Exporter,
			&i.SNMPIndex,
			&i.Description,
			&i.Alias,
			&i.Speed,
			&i.Enabled)
		if err != nil {
			log.Println("Error scanning data: ", err)
			continue
		}
		log.Println("Exporter: ", i)
		interfaces = append(interfaces, i)

	}
	return interfaces, nil
}

func getExporters() ([]Exporter, error) {
	query, err := config.db.Query("SELECT\n  id, created_at, ip_bin, ip_inet, name,\n  snmp_version, snmp_community, snmpv3_username, snmpv3_level,\n  snmpv3_auth_proto, snmpv3_auth_pass, snmpv3_priv_proto, snmpv3_priv_pass FROM exporters;")
	if err != nil {
		log.Println("Error querying database: ", err)
		return nil, err
	}
	defer func(query *sql.Rows) {
		err := query.Close()
		if err != nil {
			log.Println("Error closing query: ", err)
			return
		}
	}(query)

	var exporters []Exporter
	for query.Next() {
		var e Exporter
		err := query.Scan(
			&e.ID,
			&e.CreatedAt,
			&e.IPBin,
			&e.IPInet,
			&e.Name,
			&e.SNMPVersion,
			&e.SNMPCommunity,
			&e.SNMPv3Username,
			&e.SNMPv3Level,
			&e.SNMPv3AuthProto,
			&e.SNMPv3AuthPass,
			&e.SNMPv3PrivProto,
			&e.SNMPv3PrivPass,
		)
		if err != nil {
			log.Println("Error scanning data: ", err)
			continue
		}
		log.Println("Exporter: ", e)
		exporters = append(exporters, e)

	}
	return exporters, nil
}

func getSnmpConfig() ([]SNMPCredential, error) {
	query, err := config.db.Query("select data from config where key_name = 'snmp_config';")
	if err != nil {
		log.Println("Error querying database: ", err)
		return nil, err
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
	log.Printf("parsed credentials %v\n", creds)
	for idx, cred := range creds {
		log.Printf("creds[%d] = %v\n", idx, cred)
	}
	return creds, nil
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
			config.chExit <- true
			return
		}
	}
}

func main() {
	var err error
	config.chExit = make(chan bool)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
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

	config.start = time.Now()

	config.snmp, err = getSnmpConfig()
	if err != nil {
		panic(err)
	}
	config.exporters, err = getExporters()
	for _, e := range config.exporters {
		exporter := e
		_, err := detectSNMPCredentials(exporter)
		if err != nil {
			return
		}
	}
	config.exporters, err = getExporters()
	config.interfaces, err = getInterfaces()

	for _, e := range config.exporters {
		exporter := e

		for _, i := range config.interfaces {
			config.wg.Add(1)
			interfac := i
			log.Println("Starting goroutine for exporter: ", exporter, " interface: ", interfac)
			go pollInterface(&exporter, &interfac, &config.wg)
		}
	}
	log.Println("Waiting for goroutines to finish...")
	config.wg.Wait()
	log.Println("All goroutines finished.")
	// Duration flag, default 10s (supports 300ms, 2s, 1m, etc.)
	go timer()
	log.Println("Running...")
	<-config.chExit
	log.Println("Exiting...")
}
