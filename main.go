package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os/exec"
	"strconv"
	"strings"
)

// tshark outputs single values as strings, multiple as arrays, so this is a wrapper to handle both cases
type FlexStrings []string

func (f *FlexStrings) UnmarshalJSON(data []byte) error {
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*f = arr
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*f = []string{s}
	return nil
}

type DbDataType int

const (
	BIT   DbDataType = 1
	BYTE  DbDataType = 2
	CHAR  DbDataType = 3
	WORD  DbDataType = 4
	INT   DbDataType = 5
	DWORD DbDataType = 6
	DINT  DbDataType = 7
	REAL  DbDataType = 8
)

func (d DbDataType) String() string {
	switch d {
	case BIT:
		return "BIT"
	case BYTE:
		return "BYTE"
	case CHAR:
		return "CHAR"
	case WORD:
		return "WORD"
	case INT:
		return "INT"
	case DWORD:
		return "DWORD"
	case DINT:
		return "DINT"
	case REAL:
		return "REAL"
	default:
		return fmt.Sprintf("Unknown(%d)", d)
	}
}

func parseDbDataType(s string) (DbDataType, error) {
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid transport type: %s", s)
	}
	dt := DbDataType(v)
	if dt < BIT || dt > REAL {
		return 0, fmt.Errorf("unknown transport type: %d", v)
	}
	return dt, nil
}

type DbAddress struct {
	Db   int
	Byte int
	Bit  int
	Type DbDataType
}

func (a DbAddress) String() string {
	s := fmt.Sprintf("DB%d.DB", a.Db)
	switch a.Type {
	case BIT:
		s += fmt.Sprintf("X%d.%d", a.Byte, a.Bit)
	case BYTE:
		s += fmt.Sprintf("B%d", a.Byte)
	case WORD, INT:
		s += fmt.Sprintf("W%d", a.Byte)
	case DWORD, DINT, REAL:
		s += fmt.Sprintf("D%d", a.Byte)
	default:
		return ""
	}
	return s
}

func convertValue(hexStr string, dataType DbDataType) (any, error) {
	data, err := hex.DecodeString(strings.ReplaceAll(hexStr, ":", ""))
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex: %w", err)
	}

	switch dataType {
	case BIT:
		if len(data) < 1 {
			return nil, fmt.Errorf("not enough bytes for BIT")
		}
		return data[0] != 0, nil
	case BYTE, CHAR:
		if len(data) < 1 {
			return nil, fmt.Errorf("not enough bytes for BYTE")
		}
		return data[0], nil
	case WORD:
		if len(data) < 2 {
			return nil, fmt.Errorf("not enough bytes for WORD")
		}
		return binary.BigEndian.Uint16(data), nil
	case INT:
		if len(data) < 2 {
			return nil, fmt.Errorf("not enough bytes for INT")
		}
		return int16(binary.BigEndian.Uint16(data)), nil
	case DWORD:
		if len(data) < 4 {
			return nil, fmt.Errorf("not enough bytes for DWORD")
		}
		return binary.BigEndian.Uint32(data), nil
	case DINT:
		if len(data) < 4 {
			return nil, fmt.Errorf("not enough bytes for DINT")
		}
		return int32(binary.BigEndian.Uint32(data)), nil
	case REAL:
		if len(data) < 4 {
			return nil, fmt.Errorf("not enough bytes for REAL")
		}
		return math.Float32frombits(binary.BigEndian.Uint32(data)), nil
	default:
		return nil, fmt.Errorf("unsupported data type: %s", dataType)
	}
}

type Packet struct {
	TimestampUnixMs string `json:"timestamp"`
	Layers          struct {
		S7Comm json.RawMessage `json:"s7comm"`
	} `json:"layers"`
}

type S7CommHeader struct {
	Rosctr int `json:"s7comm_s7comm_header_rosctr,string"`
	Func   int `json:"s7comm_s7comm_param_func,string"`
}

type S7CommJobRaw struct {
	AddrBytes     FlexStrings `json:"s7comm_s7comm_param_item_address_byte"`
	AddrBits      FlexStrings `json:"s7comm_s7comm_param_item_address_bit"`
	DBs           FlexStrings `json:"s7comm_s7comm_param_item_db"`
	TransportType FlexStrings `json:"s7comm_s7comm_param_item_transp_size"`
	PDURef        int         `json:"s7comm_s7comm_header_pduref,string"`
	ItemCount     int         `json:"s7comm_s7comm_param_itemcount,string"`
}

type S7CommAckDataRaw struct {
	PDURef    int         `json:"s7comm_s7comm_header_pduref,string"`
	ItemCount int         `json:"s7comm_s7comm_param_itemcount,string"`
	Values    FlexStrings `json:"s7comm_s7comm_resp_data"`
}

type JobData struct {
	PDURef int
	Addrs  []DbAddress
}

type AckData struct {
	PDURef int
	Values []string
}

func parseJobRequest(data json.RawMessage) (*JobData, error) {
	var raw S7CommJobRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	addrs := make([]DbAddress, 0, raw.ItemCount)
	for i := range raw.ItemCount {
		db, err := strconv.Atoi(raw.DBs[i])
		if err != nil {
			continue
		}
		byteAddr, err := strconv.Atoi(raw.AddrBytes[i])
		if err != nil {
			continue
		}
		tagType, err := parseDbDataType(raw.TransportType[i])
		if err != nil {
			continue
		}
		bit, err := strconv.Atoi(raw.AddrBits[i])
		if err != nil {
			continue
		}
		addrs = append(addrs, DbAddress{
			Db:   db,
			Byte: byteAddr,
			Bit:  bit,
			Type: tagType,
		})
	}

	return &JobData{PDURef: raw.PDURef, Addrs: addrs}, nil
}

func parseAckDataResponse(data json.RawMessage) (*AckData, error) {
	var raw S7CommAckDataRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	return &AckData{PDURef: raw.PDURef, Values: []string(raw.Values)}, nil
}

func parseS7CommHeader(data json.RawMessage) (S7CommHeader, error) {
	var header S7CommHeader
	err := json.Unmarshal(data, &header)
	return header, err
}

func processPackets(lines []string) map[string]any {
	pendingJobs := make(map[int][]*JobData)
	values := make(map[string]any)

	for i, line := range lines {
		if i%2 == 0 || len(line) == 0 {
			continue
		}

		var packet Packet
		if err := json.Unmarshal([]byte(line), &packet); err != nil {
			fmt.Println("JSON parse error:", err)
			continue
		}

		header, err := parseS7CommHeader(packet.Layers.S7Comm)
		if err != nil {
			fmt.Println("Failed to parse S7Comm header:", err)
			continue
		}

		if header.Func != 4 {
			continue
		}

		switch header.Rosctr {
		case 1:
			job, err := parseJobRequest(packet.Layers.S7Comm)
			if err != nil {
				fmt.Println(err)
				continue
			}
			pendingJobs[job.PDURef] = append(pendingJobs[job.PDURef], job)
		case 3:
			ackData, err := parseAckDataResponse(packet.Layers.S7Comm)
			if err != nil {
				fmt.Println(err)
				continue
			}
			queue, ok := pendingJobs[ackData.PDURef]
			if !ok || len(queue) == 0 {
				fmt.Printf("No matching job for PDURef %d\n", ackData.PDURef)
				continue
			}
			job := queue[0]
			pendingJobs[ackData.PDURef] = queue[1:]

			for j, addr := range job.Addrs {
				if j >= len(ackData.Values) {
					break
				}
				val, err := convertValue(ackData.Values[j], addr.Type)
				if err != nil {
					fmt.Println(err)
					continue
				}
				values[addr.String()] = val
			}
		}
	}

	return values
}

func runTshark(pcapFile string) ([]byte, error) {
	cmd := exec.Command("tshark", "-r", pcapFile, "-T", "ek", "-Y", "s7comm")
	return cmd.Output()
}

func main() {
	stdout, err := runTshark("pcap/Encoder_raw_value_242_27.3.26_morning.pcapng")
	if err != nil {
		fmt.Println(err)
		return
	}

	lines := strings.Split(string(stdout), "\n")
	values := processPackets(lines)

	for addr, val := range values {
		if strings.HasPrefix(addr, "DB70.") {
			fmt.Printf("%s = %v\n", addr, val)
		}
	}
}
