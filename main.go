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

// When there is only one address it will output "123" instead of ["123"], so need to be able to handle both
type FlexStrings []string

func (f *FlexStrings) UnmarshalJSON(data []byte) error {
	// Try array first
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*f = arr
		return nil
	}
	// Fall back to single string
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*f = []string{s}
	return nil
}

type S7CommJob struct {
	AddrBytes     FlexStrings `json:"s7comm_s7comm_param_item_address_byte"`
	AddrBits      FlexStrings `json:"s7comm_s7comm_param_item_address_bit"`
	DBs           FlexStrings `json:"s7comm_s7comm_param_item_db"`
	TransportType FlexStrings `json:"s7comm_s7comm_param_item_transp_size"`
	PDURef        int         `json:"s7comm_s7comm_header_pduref,string"`
	ItemCount     int         `json:"s7comm_s7comm_param_itemcount,string"`
}

type JobData struct {
	PDURef    int
	ItemCount int
	Addrs     []DbAddress
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

type DbAddress struct {
	Db   int
	Byte int
	Bit  int
	Type DbDataType
}

func parseDbTagType(transportType string) (DbDataType, error) {
	v, err := strconv.Atoi(transportType)
	if err != nil {
		return 0, fmt.Errorf("invalid transport type: %s", transportType)
	}
	dt := DbDataType(v)
	if dt < BIT || dt > REAL {
		return 0, fmt.Errorf("unknown transport type: %d", v)
	}
	return dt, nil
}

func convertValue(data []byte, dataType DbDataType) (any, error) {
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

func parseJobRequest(data json.RawMessage) (*JobData, error) {

	var job S7CommJob
	if err := json.Unmarshal(data, &job); err != nil {
		return nil, err
	}

	var addrs []DbAddress

	for i := range job.ItemCount {
		db, err := strconv.Atoi(job.DBs[i])
		if err != nil {
			continue
		}

		byte, err := strconv.Atoi(job.AddrBytes[i])
		if err != nil {
			continue
		}

		tagType, err := parseDbTagType(job.TransportType[i])
		if err != nil {
			continue
		}

		bit, err := strconv.Atoi(job.AddrBits[i])
		if err != nil {
			continue
		}

		addr := DbAddress{
			Db:   db,
			Byte: byte,
			Bit:  bit,
			Type: tagType,
		}

		addrs = append(addrs, addr)
	}

	return &JobData{
		Addrs:     addrs,
		ItemCount: job.ItemCount,
		PDURef:    job.PDURef,
	}, nil
}

type AckData struct {
	PDURef    int
	ItemCount int
	Values    [][]byte
}

type S7CommAckData struct {
	PDURef    int         `json:"s7comm_s7comm_header_pduref,string"`
	ItemCount int         `json:"s7comm_s7comm_param_itemcount,string"`
	Values    FlexStrings `json:"s7comm_s7comm_resp_data"`
}

func parseAckDataResponse(data json.RawMessage) (*AckData, error) {

	var ackData S7CommAckData
	if err := json.Unmarshal(data, &ackData); err != nil {
		return nil, err
	}

	var values [][]byte
	for i := range ackData.ItemCount {
		value, err := hex.DecodeString(strings.ReplaceAll(ackData.Values[i], ":", ""))
		if err != nil {
			continue
		}
		values = append(values, value)
	}

	return &AckData{
		PDURef:    ackData.PDURef,
		ItemCount: ackData.ItemCount,
		Values:    values,
	}, nil
}

func main() {
	app := "tshark"

	arg0 := "-r"
	arg1 := `pcap/Encoder_raw_value_242_27.3.26_morning.pcapng`
	arg2 := "-T"
	arg3 := "ek"
	arg4 := "-Y"
	arg5 := "s7comm"

	cmd := exec.Command(app, arg0, arg1, arg2, arg3, arg4, arg5)
	stdout, err := cmd.Output()
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	lines := strings.Split(string(stdout), "\n")

	pendingJobs := make(map[int]*JobData) // keyed by PDURef
	values := make(map[string]any)        // keyed by Siemens address string

	for i, line := range lines {

		if i%2 == 0 || len(line) == 0 {
			continue
		}

		var packet Packet
		if err := json.Unmarshal([]byte(line), &packet); err != nil {
			fmt.Println("JSON parse error:", err)
			continue
		}

		s7CommData := packet.Layers.S7Comm

		var header S7CommHeader
		if err := json.Unmarshal(s7CommData, &header); err != nil {
			fmt.Println("Failed to parse S7Comm Rosctr header:", err)
			continue
		}

		// We only care about read requests (4) not writes (5)
		if header.Func != 4 {
			continue
		}

		switch header.Rosctr {
		case 1:
			job, err := parseJobRequest(s7CommData)
			if err != nil {
				fmt.Println(err)
				continue
			}
			pendingJobs[job.PDURef] = job
		case 3:
			ackData, err := parseAckDataResponse(s7CommData)
			if err != nil {
				fmt.Println(err)
				continue
			}
			job, ok := pendingJobs[ackData.PDURef]
			if !ok {
				fmt.Printf("No matching job for PDURef %d\n", ackData.PDURef)
				continue
			}
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
			delete(pendingJobs, ackData.PDURef)
		}

	}

	for addr, val := range values {
		if addr == "DB190.DBD360" {
			fmt.Printf("%s = %v\n", addr, val)
		}
	}
}
