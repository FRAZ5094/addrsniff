package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// tshark -r pcap/Encoder_raw_value_242_27.3.26_morning.pcapng -T ek -Y "s7comm" -c 3 | tail -n 1 | jq 'select(.layers) | .layers.s7comm' >> s7ackdata.json

// const (
// 	Job      Rosctr = 1
// 	Ack      Rosctr = 2
// 	AckData  Rosctr = 3
// 	UserData Rosctr = 7
// )

// func (r *Rosctr) UnmarshalJSON(data []byte) error {
// 	var str string
// 	if err := json.Unmarshal(data, &str); err != nil {
// 		return fmt.Errorf("failed to unmarshal rosctr to string: %w", err)
// 	}

// 	var rosctr Rosctr

// 	switch str {
// 	case "1":
// 		rosctr = Job
// 	case "2":
// 		rosctr = Ack
// 	case "3":
// 		rosctr = AckData
// 	case "7":
// 		rosctr = UserData
// 	default:
// 		return fmt.Errorf("invalid value for rosctr in s7comms header:%s", str)
// 	}

// 	*r = rosctr

// 	return nil
// }

// func (r Rosctr) String() string {
// 	switch r {
// 	case Job:
// 		return "Job"
// 	case Ack:
// 		return "Ack"
// 	case AckData:
// 		return "AckData"
// 	case UserData:
// 		return "UserData"
// 	default:
// 		return fmt.Sprintf("Unknown Rosctr: %d", r)
// 	}
// }

type Packet struct {
	TimestampUnixMs string `json:"timestamp"`
	Layers          struct {
		S7Comm json.RawMessage `json:"s7comm"`
	} `json:"layers"`
}

type S7CommHeader struct {
	Rosctr string `json:"s7comm_s7comm_header_rosctr"`
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
	DBs           FlexStrings `json:"s7comm_s7comm_param_item_db"`
	TransportType FlexStrings `json:"s7comm_s7comm_param_item_transp_size"`
	ItemCount     int         `json:"s7comm_s7comm_param_itemcount,string"`
}

type JobData struct {
	Addrs []DbAddress
}

func (a DbAddress) String() string {
	s := fmt.Sprintf("DB%d.DB", a.Db)

	switch a.Type {
	case "BIT":
		s += fmt.Sprintf("X%d.0", a.Byte)
	case "BYTE":
		s += fmt.Sprintf("B%d", a.Byte)
	case "WORD", "INT":
		s += fmt.Sprintf("W%d", a.Byte)
	case "DWORD", "DINT", "REAL":
		s += fmt.Sprintf("D%d", a.Byte)
	default:
		return ""
	}

	return s
}

type DbAddress struct {
	Db   int
	Byte int
	Type string
}

func parseDbTagType(transportType string) (string, error) {
	switch transportType {
	case "1":
		return "BIT", nil
	case "2":
		return "BYTE", nil
	case "3":
		return "CHAR", nil
	case "4":
		return "WORD", nil
	case "5":
		return "INT", nil
	case "6":
		return "DWORD", nil
	case "7":
		return "DINT", nil
	case "8":
		return "REAL", nil
	default:
		return "Unknown", fmt.Errorf("invalid transport type: %s", transportType)
	}
}

type AckData struct {
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

		addr := DbAddress{
			Db:   db,
			Byte: byte,
			Type: tagType,
		}

		addrs = append(addrs, addr)
	}

	return &JobData{
		Addrs: addrs,
	}, nil
}

func parseAckDataResponse(data json.RawMessage) *AckData {

	return &AckData{}
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

	var jobPackets []JobData

	for i, line := range lines {

		if i%2 == 0 || len(line) == 0 {
			continue
		}

		var packet Packet
		if err := json.Unmarshal([]byte(line), &packet); err != nil {
			fmt.Println("JSON parse error:", err)
		}

		s7CommData := packet.Layers.S7Comm

		var header S7CommHeader
		if err := json.Unmarshal(s7CommData, &header); err != nil {
			fmt.Println("Failed to parse S7Comm Rosctr header:", err)
		}

		switch header.Rosctr {
		case "1":
			if job, err := parseJobRequest(s7CommData); err != nil {
				fmt.Println(err)
			} else {
				jobPackets = append(jobPackets, *job)
			}
		case "3":
			parseAckDataResponse(s7CommData)
		default:
			// fmt.Println("Skipping rosctr of ", header.Rosctr)
		}

	}

	fmt.Println(jobPackets[0])

	// var packets []Packet

	// if err := json.Unmarshal(stdout, &packets); err != nil {
	// 	fmt.Println("JSON parse error:", err)
	// 	return
	// }

	// // fmt.Println("Packet count:", len(packets))
	// fmt.Println(packets)

}
