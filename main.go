package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	// "fmt"
	"log"
	"sort"
	// "net"
	"os"
	"regexp"

	"github.com/awslabs/aws-sdk-go/service/ec2"
	// "golang.org/x/crypto/ssh"
)

var EscapeRE = regexp.MustCompile("\x1b\\[[^a-zA-Z\\[\\]]*?[a-zA-Z]|\r")
var FingerprintRE = regexp.MustCompile("([0-9a-f]{2}(:|\\b)){16}")

func StripEscapes(bs []byte) []byte {
	return EscapeRE.ReplaceAll(bs, []byte{})
}

// Idea: connect to host and obtain the key, so that it can be added to
// 			known_hosts automatically.
// Problem: Computing the host key is not entirely trivial. (It might be but
// 	  		requires looking)

// func GetHostKey(where string) {
// 	config := &ssh.ClientConfig{
// 		User: "",
// 		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
// 			b := key.Marshal()
// 			log.Printf("HK: %q", b)
// 			return fmt.Errorf("Abort connection")
// 		},
// 	}

// 	// Dial your ssh server.
// 	conn, err := ssh.Dial("tcp", where+":22", config)
// 	if err != nil {
// 		// Connection normally aborts.
// 		return
// 	}
// 	defer conn.Close()
// }

func PrettyTags(in []*ec2.Tag) string {
	var result []string
	for _, t := range in {
		if strings.HasPrefix(*t.Key, "aws:") {
			// Skip over AWS tags
			continue
		}
		result = append(result, fmt.Sprint(*t.Key, "=", *t.Value))
	}
	sort.Strings(result)
	return strings.Join(result, " ")
}

func GetFingerprintLines(client *ec2.EC2, instance *ec2.Instance) [][]byte {

	resp, err := client.GetConsoleOutput(&ec2.GetConsoleOutputInput{
		InstanceID: instance.InstanceID,
	})
	if err != nil {
		log.Fatal(err)
	}
	if resp.Output == nil {
		return [][]byte{}
	}
	out, err := base64.StdEncoding.DecodeString(*resp.Output)
	if err != nil {
		log.Fatal(err)
	}
	out = StripEscapes(out)

	lines := bytes.SplitAfter(out, []byte("\n"))

	seen := map[string]struct{}{}

	var fingerprintLines [][]byte
	for _, line := range lines {
		if _, ok := seen[string(line)]; ok {
			continue
		}
		if FingerprintRE.Match(line) {
			fingerprintLines = append(fingerprintLines, line)
			seen[string(line)] = struct{}{}
		}
	}
	return fingerprintLines
}

func main() {

	log.SetFlags(0) // No log timestamp

	client := ec2.New(nil)

	ec2Instances, err := client.DescribeInstances(&ec2.DescribeInstancesInput{})
	if err != nil {
		log.Fatal(err)
	}

	for _, r := range ec2Instances.Reservations {
		for _, i := range r.Instances {
			if i.PublicIPAddress == nil {
				// Ignore unavailable instances
				continue
			}

			fingerprints := GetFingerprintLines(client, i)

			if len(fingerprints) > 0 {
				log.Println(*i.PublicIPAddress, PrettyTags(i.Tags))

				for _, l := range fingerprints {
					_, err := os.Stdout.Write(l)
					if err != nil {
						log.Fatal(err)
					}
				}
				fmt.Fprintln(os.Stdout)
			}
		}
	}
}
