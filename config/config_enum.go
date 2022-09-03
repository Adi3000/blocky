// Code generated by go-enum DO NOT EDIT.
// Version:
// Revision:
// Build Date:
// Built By:

package config

import (
	"fmt"
	"strings"
)

const (
	// NetProtocolTcpUdp is a NetProtocol of type Tcp+Udp.
	// TCP and UDP protocols
	NetProtocolTcpUdp NetProtocol = iota
	// NetProtocolTcpTls is a NetProtocol of type Tcp-Tls.
	// TCP-TLS protocol
	NetProtocolTcpTls
	// NetProtocolHttps is a NetProtocol of type Https.
	// HTTPS protocol
	NetProtocolHttps
)

const _NetProtocolName = "tcp+udptcp-tlshttps"

var _NetProtocolNames = []string{
	_NetProtocolName[0:7],
	_NetProtocolName[7:14],
	_NetProtocolName[14:19],
}

// NetProtocolNames returns a list of possible string values of NetProtocol.
func NetProtocolNames() []string {
	tmp := make([]string, len(_NetProtocolNames))
	copy(tmp, _NetProtocolNames)
	return tmp
}

var _NetProtocolMap = map[NetProtocol]string{
	NetProtocolTcpUdp: _NetProtocolName[0:7],
	NetProtocolTcpTls: _NetProtocolName[7:14],
	NetProtocolHttps:  _NetProtocolName[14:19],
}

// String implements the Stringer interface.
func (x NetProtocol) String() string {
	if str, ok := _NetProtocolMap[x]; ok {
		return str
	}
	return fmt.Sprintf("NetProtocol(%d)", x)
}

var _NetProtocolValue = map[string]NetProtocol{
	_NetProtocolName[0:7]:   NetProtocolTcpUdp,
	_NetProtocolName[7:14]:  NetProtocolTcpTls,
	_NetProtocolName[14:19]: NetProtocolHttps,
}

// ParseNetProtocol attempts to convert a string to a NetProtocol.
func ParseNetProtocol(name string) (NetProtocol, error) {
	if x, ok := _NetProtocolValue[name]; ok {
		return x, nil
	}
	return NetProtocol(0), fmt.Errorf("%s is not a valid NetProtocol, try [%s]", name, strings.Join(_NetProtocolNames, ", "))
}

// MarshalText implements the text marshaller method.
func (x NetProtocol) MarshalText() ([]byte, error) {
	return []byte(x.String()), nil
}

// UnmarshalText implements the text unmarshaller method.
func (x *NetProtocol) UnmarshalText(text []byte) error {
	name := string(text)
	tmp, err := ParseNetProtocol(name)
	if err != nil {
		return err
	}
	*x = tmp
	return nil
}

const (
	// QueryLogTypeConsole is a QueryLogType of type Console.
	// use logger as fallback
	QueryLogTypeConsole QueryLogType = iota
	// QueryLogTypeNone is a QueryLogType of type None.
	// no logging
	QueryLogTypeNone
	// QueryLogTypeMysql is a QueryLogType of type Mysql.
	// MySQL or MariaDB database
	QueryLogTypeMysql
	// QueryLogTypePostgresql is a QueryLogType of type Postgresql.
	// PostgreSQL database
	QueryLogTypePostgresql
	// QueryLogTypeCsv is a QueryLogType of type Csv.
	// CSV file per day
	QueryLogTypeCsv
	// QueryLogTypeCsvClient is a QueryLogType of type Csv-Client.
	// CSV file per day and client
	QueryLogTypeCsvClient
)

const _QueryLogTypeName = "consolenonemysqlpostgresqlcsvcsv-client"

var _QueryLogTypeNames = []string{
	_QueryLogTypeName[0:7],
	_QueryLogTypeName[7:11],
	_QueryLogTypeName[11:16],
	_QueryLogTypeName[16:26],
	_QueryLogTypeName[26:29],
	_QueryLogTypeName[29:39],
}

// QueryLogTypeNames returns a list of possible string values of QueryLogType.
func QueryLogTypeNames() []string {
	tmp := make([]string, len(_QueryLogTypeNames))
	copy(tmp, _QueryLogTypeNames)
	return tmp
}

var _QueryLogTypeMap = map[QueryLogType]string{
	QueryLogTypeConsole:    _QueryLogTypeName[0:7],
	QueryLogTypeNone:       _QueryLogTypeName[7:11],
	QueryLogTypeMysql:      _QueryLogTypeName[11:16],
	QueryLogTypePostgresql: _QueryLogTypeName[16:26],
	QueryLogTypeCsv:        _QueryLogTypeName[26:29],
	QueryLogTypeCsvClient:  _QueryLogTypeName[29:39],
}

// String implements the Stringer interface.
func (x QueryLogType) String() string {
	if str, ok := _QueryLogTypeMap[x]; ok {
		return str
	}
	return fmt.Sprintf("QueryLogType(%d)", x)
}

var _QueryLogTypeValue = map[string]QueryLogType{
	_QueryLogTypeName[0:7]:   QueryLogTypeConsole,
	_QueryLogTypeName[7:11]:  QueryLogTypeNone,
	_QueryLogTypeName[11:16]: QueryLogTypeMysql,
	_QueryLogTypeName[16:26]: QueryLogTypePostgresql,
	_QueryLogTypeName[26:29]: QueryLogTypeCsv,
	_QueryLogTypeName[29:39]: QueryLogTypeCsvClient,
}

// ParseQueryLogType attempts to convert a string to a QueryLogType.
func ParseQueryLogType(name string) (QueryLogType, error) {
	if x, ok := _QueryLogTypeValue[name]; ok {
		return x, nil
	}
	return QueryLogType(0), fmt.Errorf("%s is not a valid QueryLogType, try [%s]", name, strings.Join(_QueryLogTypeNames, ", "))
}

// MarshalText implements the text marshaller method.
func (x QueryLogType) MarshalText() ([]byte, error) {
	return []byte(x.String()), nil
}

// UnmarshalText implements the text unmarshaller method.
func (x *QueryLogType) UnmarshalText(text []byte) error {
	name := string(text)
	tmp, err := ParseQueryLogType(name)
	if err != nil {
		return err
	}
	*x = tmp
	return nil
}

const (
	// StartStrategyTypeBlocking is a StartStrategyType of type Blocking.
	// synchronously download blocking lists on startup
	StartStrategyTypeBlocking StartStrategyType = iota
	// StartStrategyTypeFailOnError is a StartStrategyType of type FailOnError.
	// synchronously download blocking lists on startup and shutdown on error
	StartStrategyTypeFailOnError
	// StartStrategyTypeFast is a StartStrategyType of type Fast.
	// asyncronously download blocking lists on startup
	StartStrategyTypeFast
)

const _StartStrategyTypeName = "blockingfailOnErrorfast"

var _StartStrategyTypeNames = []string{
	_StartStrategyTypeName[0:8],
	_StartStrategyTypeName[8:19],
	_StartStrategyTypeName[19:23],
}

// StartStrategyTypeNames returns a list of possible string values of StartStrategyType.
func StartStrategyTypeNames() []string {
	tmp := make([]string, len(_StartStrategyTypeNames))
	copy(tmp, _StartStrategyTypeNames)
	return tmp
}

var _StartStrategyTypeMap = map[StartStrategyType]string{
	StartStrategyTypeBlocking:    _StartStrategyTypeName[0:8],
	StartStrategyTypeFailOnError: _StartStrategyTypeName[8:19],
	StartStrategyTypeFast:        _StartStrategyTypeName[19:23],
}

// String implements the Stringer interface.
func (x StartStrategyType) String() string {
	if str, ok := _StartStrategyTypeMap[x]; ok {
		return str
	}
	return fmt.Sprintf("StartStrategyType(%d)", x)
}

var _StartStrategyTypeValue = map[string]StartStrategyType{
	_StartStrategyTypeName[0:8]:   StartStrategyTypeBlocking,
	_StartStrategyTypeName[8:19]:  StartStrategyTypeFailOnError,
	_StartStrategyTypeName[19:23]: StartStrategyTypeFast,
}

// ParseStartStrategyType attempts to convert a string to a StartStrategyType.
func ParseStartStrategyType(name string) (StartStrategyType, error) {
	if x, ok := _StartStrategyTypeValue[name]; ok {
		return x, nil
	}
	return StartStrategyType(0), fmt.Errorf("%s is not a valid StartStrategyType, try [%s]", name, strings.Join(_StartStrategyTypeNames, ", "))
}

// MarshalText implements the text marshaller method.
func (x StartStrategyType) MarshalText() ([]byte, error) {
	return []byte(x.String()), nil
}

// UnmarshalText implements the text unmarshaller method.
func (x *StartStrategyType) UnmarshalText(text []byte) error {
	name := string(text)
	tmp, err := ParseStartStrategyType(name)
	if err != nil {
		return err
	}
	*x = tmp
	return nil
}
