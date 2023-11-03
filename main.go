package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"time"

	g "github.com/gosnmp/gosnmp"
)

var (
	arg_dest      = flag.String("dest", "127.0.0.1", "destination IP")
	arg_count     = flag.Int("count", 1, "Number of messages to send.")
	arg_sleep     = flag.Int("sleep", 0, "Number of milliseconds to sleep between messages.")
	arg_port      = flag.Int("port", 162, "Port number.")
	arg_community = flag.String("community", "public", "Community string.")
	arg_file      = flag.String("file", "trap_data.txt", "Trap data file.")
	arg_entity    = flag.String("entity", "127.0.0.1", "Entity IP address.")
)

func main() {
	flag.Parse()
	flag.VisitAll(func(f *flag.Flag) {
		fmt.Printf("%s: %s\n", f.Name, f.Value)
	})
	fmt.Println("-------")

	start := time.Now()

	destination := *arg_dest
	count := *arg_count
	sleep := *arg_sleep
	port := uint16(*arg_port)
	community := *arg_community
	trapDataFile := *arg_file
	entity := *arg_entity

	// TODO: change to waitgroup to not overwhelm host
	c := make(chan string)

	trapData, err := readTrapData(trapDataFile)
	if err != nil {
		log.Fatalf("Error reading trap data: %v", err)
	}

	for i := 0; i < count; i++ {
		fmt.Println("Creating iter: ", i)
		go sendTrap(entity, destination, port, community, trapData, c)
		time.Sleep(time.Duration(sleep) * time.Millisecond)
	}

	for i := 0; i < count; i++ {
		fmt.Println(<-c) //this is blocking.
	}

	timeElapsed := time.Since(start)
	fmt.Println("This task took ", timeElapsed, " to send ", count, " messages.")
}

func readTrapData(file string) (trapData *g.SnmpTrap, err error) {
	trapData = &g.SnmpTrap{}

	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	varbinds := make([]g.SnmpPDU, 0)

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, " => ")

		if line == "" || strings.HasPrefix(line, "Varbinds") {
			continue
		}
		if strings.HasPrefix(line, "Enterprise") {
			trapData.Enterprise = parts[1]
			continue
		}
		if strings.HasPrefix(line, "Generic") {
			trapData.GenericTrap, err = strconv.Atoi(parts[1])
			if err != nil {
				println("Error converting GenericTrap to int: ", err)
			}
			continue
		}
		if strings.HasPrefix(line, "Specific") {
			trapData.SpecificTrap, err = strconv.Atoi(parts[1])
			if err != nil {
				println("Error converting GenericTrap to int: ", err)
			}
			continue
		}

		// parts := strings.Split(line, " => ")
		if len(parts) == 2 {
			oid := parts[0]
			value := parts[1]
			varbind := g.SnmpPDU{
				Name:  oid,
				Type:  g.OctetString, // You may need to determine the correct type for your data.
				Value: value,
			}
			varbinds = append(varbinds, varbind)
		}
	}

	trapData.Variables = varbinds
	return trapData, nil
}

func sendTrap(entity string, target string, port uint16, community string, trapData *g.SnmpTrap, c chan string) {
	g.Default.Target = target
	g.Default.Port = port
	g.Default.Version = g.Version1 //g.Version2c
	g.Default.Community = community

	trapData.AgentAddress = entity

	err := g.Default.Connect()
	if err != nil {
		log.Fatalf("Connect() err: %v", err)
	}
	defer g.Default.Conn.Close()

	_, err = g.Default.SendTrap(*trapData)
	if err != nil {
		log.Fatalf("SendTrap() err: %v", err)
		c <- "!! RUN FAILED !!"
	}

	c <- "successful run"
}
