package main

import (
	"database/sql"
	"encoding/json"

	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"

	_ "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/gosnmp/gosnmp"

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
	ID             uint64    `db:"id" json:"id"`
	CreatedAt      time.Time `db:"created_at" json:"created_at"`
	Exporter       uint64    `db:"exporter" json:"exporter"`
	SNMPIndex      uint64    `db:"snmp_index" json:"snmp_index"`
	Description    string    `db:"description" json:"description,omitempty"`
	Alias          string    `db:"alias" json:"alias,omitempty"`
	Speed          uint64    `db:"speed" json:"speed,omitempty"`
	Enabled        bool      `db:"enabled" json:"enabled,omitempty"`
	Name           string    `db:"name" json:"name,omitempty"`
	Polled         uint64    `db:"polled" json:"polled,omitempty"`
	InOctets       uint64    `db:"in_octets" json:"in_octets,omitempty"`
	OutOctets      uint64    `db:"out_octets" json:"out_octets,omitempty"`
	LastInOctets   uint64    `db:"last_in_octets" json:"last_in_octets,omitempty"`
	LastOutOctets  uint64    `db:"last_out_octets" json:"last_out_octets,omitempty"`
	LastPolledAt   time.Time `db:"last_polled_at" json:"last_polled_at,omitempty"`
	InOctetsRate   float64   `db:"in_octets_rate" json:"in_octets_rate,omitempty"`
	OutOctetsRate  float64   `db:"out_octets_rate" json:"out_octets_rate,omitempty"`
	ExporterStruct Exporter
}

type Exporter struct {
	ID              uint64      `db:"id" json:"id"`
	CreatedAt       time.Time   `db:"created_at" json:"created_at"`
	IPBin           uint32      `db:"ip_bin" json:"ip_bin"`
	IPInet          string      `db:"ip_inet" json:"ip_inet"`
	Name            string      `db:"name" json:"name"`
	SNMPVersion     uint16      `db:"snmp_version" json:"snmp_version,omitempty"`
	SNMPCommunity   string      `db:"snmp_community" json:"snmp_community,omitempty"`
	SNMPv3Username  string      `db:"snmpv3_username" json:"snmpv3_username,omitempty"`
	SNMPv3Level     string      `db:"snmpv3_level" json:"snmpv3_level,omitempty"`
	SNMPv3AuthProto string      `db:"snmpv3_auth_proto" json:"snmpv3_auth_proto,omitempty"`
	SNMPv3AuthPass  string      `db:"snmpv3_auth_pass" json:"snmpv3_auth_pass,omitempty"`
	SNMPv3PrivProto string      `db:"snmpv3_priv_proto" json:"snmpv3_priv_proto,omitempty"`
	SNMPv3PrivPass  string      `db:"snmpv3_priv_pass" json:"snmpv3_priv_pass,omitempty"`
	Interfaces      []Interface `db:"interfaces" json:"interfaces,omitempty"`
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
	db        *sql.DB
	mutex     sync.Mutex
	exporters []Exporter

	snmp   []SNMPCredential
	start  time.Time
	wg     sync.WaitGroup
	chExit chan bool
}

const (
	SysUptime         = ".1.3.6.1.2.1.1.3.0"
	SysDescr          = ".1.3.6.1.2.1.1.1"
	ifDescr           = ".1.3.6.1.2.1.2.2.1.2."
	ifName            = ".1.3.6.1.2.1.31.1.1.1.1."
	ifAlias           = ".1.3.6.1.2.1.31.1.1.1.18."
	ifSpeed           = ".1.3.6.1.2.1.2.2.1.5."
	ifInOctets        = ".1.3.6.1.2.1.2.2.1.10."
	ifHCInOctets      = ".1.3.6.1.2.1.31.1.1.1.6."
	ifOutOctets       = ".1.3.6.1.2.1.2.2.1.16."
	ifHCOutOctets     = ".1.3.6.1.2.1.31.1.1.1.10."
	ifInUcastPkts     = ".1.3.6.1.2.1.2.2.1.11."
	ifOutUcastPkts    = ".1.3.6.1.2.1.2.2.1.17."
	ifInNUcastPkts    = ".1.3.6.1.2.1.2.2.1.12."
	ifOutNUcastPkts   = ".1.3.6.1.2.1.2.2.1.18."
	ifInDiscards      = ".1.3.6.1.2.1.2.2.1.13."
	ifOutDiscards     = ".1.3.6.1.2.1.2.2.1.19."
	ifInErrors        = ".1.3.6.1.2.1.2.2.1.14."
	ifOutErrors       = ".1.3.6.1.2.1.2.2.1.20."
	ifInUnknownProtos = ".1.3.6.1.2.1.2.2.1.15."
)

var config Config

func saveInterfaceMetrics(i *Interface) (bool, error) {
	var err error
	var _ sql.Result
	log.Printf("Saving interface metrics: %+v\n", i)

	_, err = config.db.Exec("INSERT into interface_metrics  (exporter,snmp_index,octets_in,octets_out,octets_in_rate,octets_out_rate) VALUES (?,?,?,?,?,?)",
		i.Exporter, i.SNMPIndex, i.InOctets, i.OutOctets, i.InOctetsRate, i.OutOctetsRate)

	if err != nil {
		log.Println("Error inserting interface metrics: ", err)
		return false, err
	}
	return true, nil
}

func saveInterfaceData(i *Interface) (bool, error) {
	var err error
	var _ sql.Result
	log.Printf("Saving interface data: %+v\n", i)
	log.Println("speed: ", i.Speed)

	_, err = config.db.Exec("ALTER TABLE interfaces UPDATE description = ?, alias = ?, speed = ?, enabled = ?, name = ? WHERE id = ?;", i.Description, i.Alias, i.Speed, i.Enabled, i.Name, i.ID)

	if err != nil {
		log.Println("Error updating interface data: ", err)
		return false, err
	}
	return true, nil
}

func saveSNMPCredentials(e Exporter, idx int, name string) (bool, error) {
	cred := config.snmp[idx]
	exporterId := e.ID
	var err error
	var _ sql.Result
	if cred.Version == 1 || cred.Version == 2 {
		_, err = config.db.Exec("ALTER TABLE exporters UPDATE snmp_version = ?, snmp_community = ? WHERE id = ?;", cred.Version, cred.Community, exporterId)
	} else if cred.Version == 3 {
		_, err = config.db.Exec("ALTER TABLE exporters UPDATE snmp_version = 3, snmpv3_username = ?, snmpv3_level = ?, snmpv3_auth_proto = ?, snmpv3_auth_pass = ?, snmpv3_priv_proto = ? , snmpv3_priv_pass = ? WHERE id = ?",
			cred.User, cred.SecurityLevel, cred.AuthProtocol, cred.AuthPassphrase, cred.PrivProtocol, cred.PrivPassphrase, exporterId)
	} else {
		err = fmt.Errorf("invalid version")

	}
	if err != nil {
		return false, err
	}
	return true, nil

}

func detectSNMPCredentials(e Exporter, wg *sync.WaitGroup) (int, error) {
	defer wg.Done()
	var g *gosnmp.GoSNMP
	var name string
	var oids []string
	oids = append(oids, ifDescr)
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
				if pdu.Value != nil {
					switch v := pdu.Value.(type) {
					case []byte:
						name = string(v)
					default:
						name = fmt.Sprintf("%v", v)
					}
				}
				log.Printf("%s = %s\n", pdu.Name, name)
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
				if pdu.Value != nil {
					switch v := pdu.Value.(type) {
					case []byte:
						name = string(v)
					default:
						name = fmt.Sprintf("%v", v)
					}
				}
				log.Printf("%s = %s\n", pdu.Name, name)
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

func pollInterfaceOctets(e *Exporter, i *Interface, wg *sync.WaitGroup) {
	defer wg.Done()
	var g *gosnmp.GoSNMP
	var oids []string
	var base_oids []string
	var ifinoctets uint64 = 0
	var ifoutoctets uint64 = 0
	var ifhcinoctets uint64 = 0
	var ifhcoutoctets uint64 = 0

	currentTime := time.Now()

	base_oids = append(base_oids, ifInOctets)
	base_oids = append(base_oids, ifOutOctets)
	base_oids = append(base_oids, ifHCInOctets)
	base_oids = append(base_oids, ifHCOutOctets)

	for _, base_oid := range base_oids {
		oid := base_oid + fmt.Sprintf("%d", i.SNMPIndex)
		log.Println("OID: ", oid)
		oids = append(oids, oid)
	}

	log.Println("Exporter: ", e, " Interface: ", i)
	log.Println("OIDs: ", oids)
	if e.SNMPVersion == 1 || e.SNMPVersion == 2 {
		var version gosnmp.SnmpVersion
		switch e.SNMPVersion {
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
			Community: e.SNMPCommunity,
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
			//log.Printf("%s = %s\n", pdu.Name, string(pdu.Value.([]byte)))
			var _ string
			var val_uint64 uint64

			if pdu.Type == gosnmp.OctetString && pdu.Value != nil {
				log.Println("pduType: OctetString")
				if b, ok := pdu.Value.([]byte); ok {
					_ = string(b)
				}
			} else if (pdu.Type == gosnmp.Gauge32 || pdu.Type == gosnmp.Counter32) && pdu.Value != nil {
				log.Println("pduType: Gauge32/Counter32")
				if v, ok := pdu.Value.(uint); ok {
					val_uint64 = uint64(v)
				}
			} else if pdu.Type == gosnmp.Counter64 && pdu.Value != nil {
				if v, ok := pdu.Value.(uint64); ok {
					val_uint64 = v
				}
			} else {
				_ = ""
				val_uint64 = 0
			}

			switch idx {
			case 0:
				ifinoctets = val_uint64
			case 1:
				ifoutoctets = val_uint64
			case 2:
				ifhcinoctets = val_uint64
			case 3:
				ifhcoutoctets = val_uint64
			}

		}

	} else if e.SNMPVersion == 3 {
		var ap gosnmp.SnmpV3MsgFlags
		var authprot gosnmp.SnmpV3AuthProtocol
		var privprot gosnmp.SnmpV3PrivProtocol
		sl := strings.ToLower(e.SNMPv3Level)
		switch sl {
		case "noauthnopriv":
			ap = gosnmp.NoAuthNoPriv
		case "authnopriv":
			ap = gosnmp.AuthNoPriv
		case "authpriv":
			ap = gosnmp.AuthPriv
		}
		capr := strings.ToUpper(e.SNMPv3AuthProto)
		switch capr {
		case "MD5":
			authprot = gosnmp.MD5
		case "SHA":
			authprot = gosnmp.SHA
		}
		pvr := strings.ToUpper(e.SNMPv3PrivProto)
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
				UserName:                 e.SNMPv3Username,
				AuthenticationProtocol:   authprot, // or gosnmp.MD5, SHA224/256 if supported
				AuthenticationPassphrase: e.SNMPv3AuthPass,
				PrivacyProtocol:          privprot, // or gosnmp.DES, AES192/256* if supported
				PrivacyPassphrase:        e.SNMPv3PrivPass,
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
			//log.Printf("%s = %s\n", pdu.Name, string(pdu.Value.([]byte)))
			var _ string
			var val_uint64 uint64

			if pdu.Type == gosnmp.OctetString && pdu.Value != nil {
				log.Println("pduType: OctetString")
				if b, ok := pdu.Value.([]byte); ok {
					_ = string(b)
				}
			} else if (pdu.Type == gosnmp.Gauge32 || pdu.Type == gosnmp.Counter32) && pdu.Value != nil {
				log.Println("pduType: Gauge32/Counter32")
				if v, ok := pdu.Value.(uint); ok {
					val_uint64 = uint64(v)
				}
			} else if pdu.Type == gosnmp.Counter64 && pdu.Value != nil {
				if v, ok := pdu.Value.(uint64); ok {
					val_uint64 = v
				}
			} else {
				_ = ""
				val_uint64 = 0
			}

			switch idx {
			case 0:
				ifinoctets = val_uint64
			case 1:
				ifoutoctets = val_uint64
			case 2:
				ifhcinoctets = val_uint64
			case 3:
				ifhcoutoctets = val_uint64
			}

		}

	}
	// Prefer 64-bit counters
	if ifhcinoctets != 0 {
		i.InOctets = ifhcinoctets
	} else {
		i.InOctets = ifinoctets
	}
	if ifhcoutoctets != 0 {
		i.OutOctets = ifhcoutoctets
	} else {
		i.OutOctets = ifoutoctets
	}

	// Calculate rates with rollover detection
	if !i.LastPolledAt.IsZero() {
		timeDiff := currentTime.Sub(i.LastPolledAt).Seconds()
		if timeDiff > 0 {
			// Handle InOctets
			var inDiff uint64
			if i.InOctets < i.LastInOctets {
				// Counter rolled over
				var maxCounter uint64
				if ifhcinoctets != 0 {
					maxCounter = ^uint64(0) // 2^64 - 1 for Counter64
				} else {
					maxCounter = uint64(^uint32(0)) // 2^32 - 1 for Counter32
				}
				inDiff = (maxCounter - i.LastInOctets) + i.InOctets + 1
				log.Printf("InOctets rollover detected: last=%d, current=%d, diff=%d", i.LastInOctets, i.InOctets, inDiff)
			} else {
				inDiff = i.InOctets - i.LastInOctets
			}
			i.InOctetsRate = float64(inDiff) / timeDiff

			// Handle OutOctets
			var outDiff uint64
			if i.OutOctets < i.LastOutOctets {
				// Counter rolled over
				var maxCounter uint64
				if ifhcoutoctets != 0 {
					maxCounter = ^uint64(0) // 2^64 - 1 for Counter64
				} else {
					maxCounter = uint64(^uint32(0)) // 2^32 - 1 for Counter32
				}
				outDiff = (maxCounter - i.LastOutOctets) + i.OutOctets + 1
				log.Printf("OutOctets rollover detected: last=%d, current=%d, diff=%d", i.LastOutOctets, i.OutOctets, outDiff)
			} else {
				outDiff = i.OutOctets - i.LastOutOctets
			}
			i.OutOctetsRate = float64(outDiff) / timeDiff

			log.Printf("Interface %d rates: In=%.2f octets/s, Out=%.2f octets/s", i.SNMPIndex, i.InOctetsRate, i.OutOctetsRate)
		}
	}

	// Update last values for next poll
	_, err := config.db.Exec("ALTER TABLE interfaces UPDATE last_in_octets = ?, last_out_octets = ?, last_polled_at = ? WHERE id = ?;",
		i.InOctets, i.OutOctets, currentTime, i.ID)
	if err != nil {
		log.Println("Error updating last polled values: ", err)
	}

	b, err := saveInterfaceMetrics(i)
	if err != nil {
		log.Println("Could not save interface: ", err)
		return
	}
	if b {
		log.Println("Interface saved")
	}

}

func pollInterfaceData(e *Exporter, i *Interface, wg *sync.WaitGroup) {
	defer wg.Done()
	var g *gosnmp.GoSNMP
	var oids []string
	var base_oids []string
	base_oids = append(base_oids, ifName)
	base_oids = append(base_oids, ifDescr)
	base_oids = append(base_oids, ifAlias)
	base_oids = append(base_oids, ifSpeed)

	for _, base_oid := range base_oids {
		oid := base_oid + fmt.Sprintf("%d", i.SNMPIndex)
		log.Println("OID: ", oid)
		oids = append(oids, oid)
	}

	log.Println("Exporter: ", e, " Interface: ", i)
	log.Println("OIDs: ", oids)
	if e.SNMPVersion == 1 || e.SNMPVersion == 2 {
		var version gosnmp.SnmpVersion
		switch e.SNMPVersion {
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
			Community: e.SNMPCommunity,
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
			//log.Printf("%s = %s\n", pdu.Name, string(pdu.Value.([]byte)))
			var val_string string
			var val_uint64 uint64
			log.Println("idx: ", idx)

			if pdu.Type == gosnmp.OctetString && pdu.Value != nil {
				log.Println("pduType: OctetString")
				if b, ok := pdu.Value.([]byte); ok {
					val_string = string(b)
				}
			} else if (pdu.Type == gosnmp.Gauge32 || pdu.Type == gosnmp.Counter32) && pdu.Value != nil {
				log.Println("pduType: Gauge32/Counter32")
				if v, ok := pdu.Value.(uint); ok {
					val_uint64 = uint64(v)
				}
				log.Println("Value: ", val_uint64, "")
			} else if pdu.Type == gosnmp.Counter64 && pdu.Value != nil {
				log.Println("pduType: Counter64")
				if v, ok := pdu.Value.(uint64); ok {
					val_uint64 = v
				}
				log.Println("Value: ", val_uint64, "")
			} else {
				val_string = ""
				val_uint64 = 0
			}

			switch idx {
			case 0:
				i.Name = val_string
			case 1:
				i.Description = val_string
			case 2:
				i.Alias = val_string
			case 3:
				log.Println("Speed: ", val_uint64)
				i.Speed = val_uint64
			}
		}

	} else if e.SNMPVersion == 3 {
		var ap gosnmp.SnmpV3MsgFlags
		var authprot gosnmp.SnmpV3AuthProtocol
		var privprot gosnmp.SnmpV3PrivProtocol
		sl := strings.ToLower(e.SNMPv3Level)
		switch sl {
		case "noauthnopriv":
			ap = gosnmp.NoAuthNoPriv
		case "authnopriv":
			ap = gosnmp.AuthNoPriv
		case "authpriv":
			ap = gosnmp.AuthPriv
		}
		capr := strings.ToUpper(e.SNMPv3AuthProto)
		switch capr {
		case "MD5":
			authprot = gosnmp.MD5
		case "SHA":
			authprot = gosnmp.SHA
		}
		pvr := strings.ToUpper(e.SNMPv3PrivProto)
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
				UserName:                 e.SNMPv3Username,
				AuthenticationProtocol:   authprot, // or gosnmp.MD5, SHA224/256 if supported
				AuthenticationPassphrase: e.SNMPv3AuthPass,
				PrivacyProtocol:          privprot, // or gosnmp.DES, AES192/256* if supported
				PrivacyPassphrase:        e.SNMPv3PrivPass,
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
			//log.Printf("%s = %s\n", pdu.Name, string(pdu.Value.([]byte)))
			var val_string string
			var val_uint64 uint64

			if pdu.Type == gosnmp.OctetString && pdu.Value != nil {
				log.Println("pduType: OctetString")
				if b, ok := pdu.Value.([]byte); ok {
					val_string = string(b)
				}
			} else if (pdu.Type == gosnmp.Gauge32 || pdu.Type == gosnmp.Counter32) && pdu.Value != nil {
				log.Println("pduType: Gauge32/Counter32")
				if v, ok := pdu.Value.(uint); ok {
					val_uint64 = uint64(v)
				}
				log.Println("Value: ", val_uint64, "")
			} else if pdu.Type == gosnmp.Counter64 && pdu.Value != nil {
				log.Println("pduType: Counter64")
				if v, ok := pdu.Value.(uint64); ok {
					val_uint64 = v
				}
				log.Println("Value: ", val_uint64, "")
			} else {
				val_string = ""
				val_uint64 = 0
			}

			switch idx {
			case 0:
				i.Name = val_string
			case 1:
				i.Description = val_string
			case 2:
				i.Alias = val_string
			case 3:
				log.Println("Speed: ", val_uint64)
				i.Speed = val_uint64
			}
		}

	}
	b, err := saveInterfaceData(i)
	if err != nil {
		log.Println("Could not save interface: ", err)
		return
	}
	if b {
		log.Println("Interface saved")
	}

}

func getInterfaces(e Exporter) ([]Interface, error) {
	query, err := config.db.Query("SELECT\n  id, created_at, exporter, snmp_index, description, alias,speed,enabled,last_in_octets,last_out_octets,last_polled_at   FROM interfaces where exporter = ?;", e.IPBin)
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
	var idesc sql.NullString
	var ialias sql.NullString
	var ispeed sql.NullInt64
	var ienabled sql.NullBool
	var ilastinoctets sql.NullInt64
	var ilastoutoctets sql.NullInt64
	var ilastpolledat sql.NullTime
	for query.Next() {
		var i Interface
		err := query.Scan(
			&i.ID,
			&i.CreatedAt,
			&i.Exporter,
			&i.SNMPIndex,
			&idesc,
			&ialias,
			&ispeed,
			&ienabled,
			&ilastinoctets,
			&ilastoutoctets,
			&ilastpolledat)
		if err != nil {
			log.Println("Error scanning data: ", err)
			continue
		}
		if idesc.Valid {
			i.Description = idesc.String
		}
		if ialias.Valid {
			i.Alias = ialias.String
		}
		if ispeed.Valid {
			i.Speed = uint64(ispeed.Int64)
		}
		if ienabled.Valid {
			i.Enabled = ienabled.Bool
		}
		if ilastinoctets.Valid {
			i.LastInOctets = uint64(ilastinoctets.Int64)
		}
		if ilastoutoctets.Valid {
			i.LastOutOctets = uint64(ilastoutoctets.Int64)
		}
		if ilastpolledat.Valid {
			i.LastPolledAt = ilastpolledat.Time
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

		var sqlname sql.NullString
		var sqlsnmpver sql.NullInt64
		var sqlsnmpcom sql.NullString
		var sqlsnmpuser sql.NullString
		var sqlsnmplevel sql.NullString
		var sqlsnmpauthproto sql.NullString
		var sqlsnmpauthpass sql.NullString
		var sqlsnmpprivproto sql.NullString
		var sqlsnmpprivpass sql.NullString

		err := query.Scan(
			&e.ID,
			&e.CreatedAt,
			&e.IPBin,
			&e.IPInet,
			&sqlname,
			&sqlsnmpver,
			&sqlsnmpcom,
			&sqlsnmpuser,
			&sqlsnmplevel,
			&sqlsnmpauthproto,
			&sqlsnmpauthpass,
			&sqlsnmpprivproto,
			&sqlsnmpprivpass,
		)
		if sqlname.Valid {
			e.Name = sqlname.String
		}
		if sqlsnmpcom.Valid {
			e.SNMPCommunity = sqlsnmpcom.String
		}
		if sqlsnmpuser.Valid {
			e.SNMPv3Username = sqlsnmpuser.String
		}
		if sqlsnmpver.Valid {
			e.SNMPVersion = uint16(sqlsnmpver.Int64)
		}
		if sqlsnmplevel.Valid {
			e.SNMPv3Level = sqlsnmplevel.String
		}
		if sqlsnmpauthproto.Valid {
			e.SNMPv3AuthProto = sqlsnmpauthproto.String
		}
		if sqlsnmpauthpass.Valid {
			e.SNMPv3AuthPass = sqlsnmpauthpass.String
		}
		if sqlsnmpprivproto.Valid {
			e.SNMPv3PrivProto = sqlsnmpprivproto.String
		}
		if sqlsnmpprivpass.Valid {
			e.SNMPv3PrivPass = sqlsnmpprivpass.String
		}
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
	timer := 0
	ticker := time.NewTicker(60 * time.Second)
	defer func(t *time.Ticker) {
		ticker.Stop()

	}(ticker)

	// Handle Ctrl+C to cancel early
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	for {

		select {
		case <-ticker.C:
			timer += 1
			log.Println("tick...", timer, " minutes elapsed")

			if timer%60 == 0 {
				go func() {
					config.exporters, _ = getExporters()
					for idx, e := range config.exporters {
						config.exporters[idx].Interfaces, _ = getInterfaces(e)
					}
					for idx, e := range config.exporters {
						exporter := e
						config.wg.Add(1)
						go func() {
							_, err := detectSNMPCredentials(config.exporters[idx], &config.wg)
							if err != nil {
								log.Println("Error detecting SNMP credentials: ", err)
							}
						}()
						for idx := range exporter.Interfaces {
							if exporter.Interfaces[idx].Enabled {
								config.wg.Add(1)
								log.Println("Polling interface: ", exporter.Interfaces[idx])
								go pollInterfaceData(&e, &exporter.Interfaces[idx], &config.wg)
							}
						}

					}
					log.Println("Waiting for all pollInterfaceData goroutines to finish...")
					config.wg.Wait()
					log.Println("All done!!")
					log.Println(config)
				}()
			}
			if timer%1 == 0 {
				var configTimerPollInterfaces Config
				configTimerPollInterfaces.exporters, _ = getExporters()
				for idx, e := range configTimerPollInterfaces.exporters {
					configTimerPollInterfaces.exporters[idx].Interfaces, _ = getInterfaces(e)
				}
				for idx := range configTimerPollInterfaces.exporters {
					log.Println(configTimerPollInterfaces.exporters[idx])
					for jdx := range configTimerPollInterfaces.exporters[idx].Interfaces {
						log.Println(configTimerPollInterfaces.exporters[idx].Interfaces[jdx])
						if configTimerPollInterfaces.exporters[idx].Interfaces[jdx].Enabled {
							configTimerPollInterfaces.wg.Add(1)
							log.Printf("Polling interface: %s (%d) on exporter %s\n", config.exporters[idx].Interfaces[jdx].Description, config.exporters[idx].Interfaces[jdx].SNMPIndex, config.exporters[idx].IPInet)
							go func(ex *Exporter, interf *Interface) {
								pollInterfaceOctets(ex, interf, &configTimerPollInterfaces.wg)
							}(&configTimerPollInterfaces.exporters[idx], &configTimerPollInterfaces.exporters[idx].Interfaces[jdx])
						}
					}
				}
				log.Println("Waiting for all pollInterfaceData goroutines to finish...")
				configTimerPollInterfaces.wg.Wait()
				log.Println("All done!!")
				log.Println(configTimerPollInterfaces)
			}

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
	connString := os.Getenv("CH_CONN_STRING")
	if connString == "" {
		connString = "clickhouse://127.0.0.1:9000/default"
	}
	log.Println("Connecting to database: ", connString)
	config.db, err = sql.Open("clickhouse", connString)
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
	/*
		for _, e := range config.exporters {
			config.wg.Add(1)
			exporter := e
			go func(ex Exporter) {
				_, err := detectSNMPCredentials(ex, &config.wg)
				if err != nil {
					log.Println("Error detecting SNMP credentials for ", ex.IPInet, ": ", err)
				}
			}(exporter)
		}
		config.wg.Wait()

	*/
	config.exporters, _ = getExporters()
	for idx, e := range config.exporters {
		config.exporters[idx].Interfaces, _ = getInterfaces(e)
	}

	for idx := range config.exporters {
		for jdx := range config.exporters[idx].Interfaces {
			config.wg.Add(1)
			log.Printf("Starting goroutine for exporter: %s (%d) interface: %s (%d)\n", config.exporters[idx].IPInet, config.exporters[idx].ID, config.exporters[idx].Interfaces[jdx].Description, config.exporters[idx].Interfaces[jdx].SNMPIndex)
			go func(ex *Exporter, interf *Interface) {
				pollInterfaceData(ex, interf, &config.wg)
			}(&config.exporters[idx], &config.exporters[idx].Interfaces[jdx])

			config.wg.Add(1)
			go func(ex *Exporter, interf *Interface) {
				pollInterfaceOctets(ex, interf, &config.wg)
			}(&config.exporters[idx], &config.exporters[idx].Interfaces[jdx])
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
