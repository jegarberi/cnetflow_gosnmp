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
	ID             int64     `db:"id" json:"id"`
	CreatedAt      time.Time `db:"created_at" json:"created_at"`
	Exporter       int64     `db:"exporter" json:"exporter"`
	SNMPIndex      int64     `db:"snmp_index" json:"snmp_index"`
	Description    string    `db:"description" json:"description,omitempty"`
	Alias          string    `db:"alias" json:"alias,omitempty"`
	Speed          uint64    `db:"speed" json:"speed,omitempty"`
	Enabled        bool      `db:"enabled" json:"enabled,omitempty"`
	Name           string    `db:"name" json:"name,omitempty"`
	Polled         uint64    `db:"polled" json:"polled,omitempty"`
	InOctets       uint64    `db:"in_octets" json:"in_octets,omitempty"`
	OutOctets      uint64    `db:"out_octets" json:"out_octets,omitempty"`
	ExporterStruct Exporter
}

type Exporter struct {
	ID              int64       `db:"id" json:"id"`
	CreatedAt       time.Time   `db:"created_at" json:"created_at"`
	IPBin           int32       `db:"ip_bin" json:"ip_bin"`
	IPInet          string      `db:"ip_inet" json:"ip_inet"`
	Name            string      `db:"name" json:"name"`
	SNMPVersion     int16       `db:"snmp_version" json:"snmp_version,omitempty"`
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
	SysDescr          = ".1.3.6.1.2.1.1.1.0"
	ifDescr           = ".1.3.6.1.2.1.2.2.1.2."
	ifName            = ".1.3.6.1.2.1.31.1.1.1.1."
	ifAlias           = ".1.3.6.1.2.1.31.1.1.1.18."
	ifSpeed           = ".1.3.6.1.2.1.2.2.1.5."
	ifInOctets        = ".1.3.6.1.2.1.2.2.1.10."
	ifHCInOctets      = ".1.3.6.1.2.1.31.1.1.1.6."
	ifOutOctets       = ".1.3.6.1.2.1.2.2.1.16."
	ifHCOutOctets     = "1.3.6.1.2.1.31.1.1.1.10."
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
	log.Println("Saving interface: ", i)

	_, err = config.db.Exec("INSERT into interface_metrics  (exporter,snmp_index,octets_in,octets_out,timestamp) VALUES (?,?,?,?,?)", i.Exporter, i.SNMPIndex, i.InOctets, i.OutOctets, time.Now())

	if err != nil {
		return false, err
	}
	return true, nil
}

func saveInterfaceData(i *Interface) (bool, error) {
	var err error
	var _ sql.Result
	log.Println("Saving interface: ", i)
	log.Println("speed: ", i.Speed)

	_, err = config.db.Exec("ALTER TABLE interfaces UPDATE description = ?, alias = ?, speed = ?, enabled = ?, name = ? WHERE id = ?;", i.Description, i.Alias, i.Speed, i.Enabled, i.Name, i.ID)

	if err != nil {
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
		_, err = config.db.Exec("ALTER TABLE exporters UPDATE snmp_version = ?, snmp_community = ?, name = ? WHERE id = ?;", cred.Version, cred.Community, name, exporterId)
	} else if cred.Version == 3 {
		_, err = config.db.Exec("ALTER TABLE exporters UPDATE snmp_version = 3, snmpv3_username = ?, snmpv3_level = ?, snmpv3_auth_proto = ?, snmpv3_auth_pass = ?, snmpv3_priv_proto = ? , snmpv3_priv_pass = ?, name = ? WHERE id = ?",
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

func pollInterfaceOctets(e *Exporter, i *Interface, wg *sync.WaitGroup) {
	defer wg.Done()
	var g *gosnmp.GoSNMP
	var oids []string
	var base_oids []string
	var ifinoctets uint64 = 0
	var ifoutoctets uint64 = 0
	var ifhcinoctets uint64 = 0
	var ifhcoutoctets uint64 = 0

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

			if pdu.Type == gosnmp.OctetString {
				log.Println("pduType: OctetString")
				_ = fmt.Sprintf("%s", string(pdu.Value.([]byte)))
			} else if pdu.Type == gosnmp.Gauge32 {
				log.Println("pduType: Gauge32")
				val_uint64 = uint64(pdu.Value.(uint))
				log.Println("Gauge32: ", val_uint64, "")
			} else if pdu.Type == gosnmp.Counter32 {
				val_uint64 = uint64(pdu.Value.(uint))
			} else if pdu.Type == gosnmp.Counter64 {
				val_uint64 = pdu.Value.(uint64)
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

			if pdu.Type == gosnmp.OctetString {
				log.Println("pduType: OctetString")
				_ = fmt.Sprintf("%s", string(pdu.Value.([]byte)))
			} else if pdu.Type == gosnmp.Gauge32 {
				log.Println("pduType: Gauge32")
				val_uint64 = uint64(pdu.Value.(uint))
				log.Println("Gauge32: ", val_uint64, "")
			} else if pdu.Type == gosnmp.Counter32 {
				val_uint64 = uint64(pdu.Value.(uint))
			} else if pdu.Type == gosnmp.Counter64 {
				val_uint64 = pdu.Value.(uint64)
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
			if pdu.Type == gosnmp.OctetString {
				log.Println("pduType: OctetString")
				val_string = fmt.Sprintf("%s", string(pdu.Value.([]byte)))
			} else if pdu.Type == gosnmp.Gauge32 {
				log.Println("pduType: Gauge32")
				val_uint64 = uint64(pdu.Value.(uint))
				log.Println("Gauge32: ", val_uint64, "")
			} else {
				val_string = ""
				val_uint64 = 0
			}

			switch idx {
			case 0:
				i.Name = val_string
			case 1:
				i.Alias = val_string
			case 2:
				i.Description = val_string
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
			if pdu.Type == gosnmp.OctetString {
				log.Println("pduType: OctetString")
				val_string = fmt.Sprintf("%s", string(pdu.Value.([]byte)))
			} else if pdu.Type == gosnmp.Gauge32 {
				log.Println("pduType: Gauge32")
				val_uint64 = uint64(pdu.Value.(uint))
				log.Println("Gauge32: ", val_uint64, "")
			} else {
				val_string = ""
				val_uint64 = 0
			}

			switch idx {
			case 0:
				i.Name = val_string
			case 1:
				i.Alias = val_string
			case 2:
				i.Description = val_string
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
	query, err := config.db.Query("SELECT\n  id, created_at, exporter, snmp_index, description, alias,speed,enabled   FROM interfaces where exporter = ?;", e.ID)
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
			&ienabled)
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
			e.SNMPVersion = int16(sqlsnmpver.Int64)
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
				config.exporters, _ = getExporters()
				for idx, e := range config.exporters {
					config.exporters[idx].Interfaces, _ = getInterfaces(e)
				}
				for idx, e := range config.exporters {
					exporter := e
					detectSNMPCredentials(config.exporters[idx])
					for _, i := range exporter.Interfaces {
						if i.Enabled {
							config.wg.Add(1)
							log.Println("Polling interface: ", i)
							go pollInterfaceData(&e, &i, &config.wg)
						}
					}

				}
				log.Println("Waiting for all pollInterfaceData goroutines to finish...")
				config.wg.Wait()
				log.Println("All done!!")
				log.Println(config)
			}
			if timer%1 == 0 {
				for _, e := range config.exporters {
					log.Println(e)
					for _, i := range e.Interfaces {
						log.Println(i)
						if i.Enabled {
							config.wg.Add(1)
							log.Println("Polling interface: ", i)
							go pollInterfaceOctets(&e, &i, &config.wg)
						}
					}
				}
				log.Println("Waiting for all pollInterfaceData goroutines to finish...")
				config.wg.Wait()
				log.Println("All done!!")
				log.Println(config)
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
	for _, e := range config.exporters {
		exporter := e
		_, err := detectSNMPCredentials(exporter)
		if err != nil {
			log.Println("Error detecting SNMP credentials: ", err)
		}
	}
	config.exporters, _ = getExporters()
	for idx, e := range config.exporters {
		config.exporters[idx].Interfaces, _ = getInterfaces(e)
	}

	for _, e := range config.exporters {
		exporter := e
		for _, i := range exporter.Interfaces {
			config.wg.Add(1)
			interfac := i
			log.Println("Starting goroutine for exporter: ", exporter, " interface: ", interfac)
			go pollInterfaceData(&exporter, &interfac, &config.wg)
			config.wg.Add(1)
			go pollInterfaceOctets(&exporter, &interfac, &config.wg)
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
