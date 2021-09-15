package main

import (
	"context"
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	"github.com/florianl/go-nflog/v2"
)

const (
	table       = "filter"
	chain       = "nflog"
	nflog_group = "100"
)

func initIptable() error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return err
	}
	ipt.ClearChain(table, chain)
	ipt.Delete(table, "INPUT", "-j", chain)
	err = ipt.Insert(table, "INPUT", 1, "-j", chain)
	portRange := fmt.Sprintf("%v:%v", 20, 65535)

	rulespec := ruleSpec("tcp", portRange)
	if err = ipt.AppendUnique(table, chain, rulespec...); err != nil {
		return err
	}
	syncRule := synRuleSpec("tcp", portRange)
	if err = ipt.AppendUnique(table, chain, syncRule...); err != nil {
		return err
	}
	return nil
}

// ruleSpec
func ruleSpec(proto, dportStr string) (rulespec []string) {
	rulespec = []string{
		"-p", proto,
		"-m", proto,
		"-m", "multiport",
		"--dports", dportStr,
		"--tcp-flags", "FIN,SYN,RST,PSH,ACK,URG", "FIN,PSH,URG",
		"-j", "NFLOG",
		"--nflog-group", nflog_group,
	}
	return rulespec
}

// syn rulespec
func synRuleSpec(proto, dportStr string) (rulespec []string) {
	rulespec = []string{
		"-p", proto,
		"-m", proto,
		"-m", "multiport",
		"--dports", dportStr,
		"--tcp-flags", "FIN,SYN,RST,PSH,ACK,URG", "SYN",
		"-j", "NFLOG",
		"--nflog-group", nflog_group,
	}
	return rulespec
}

func callback(attrs nflog.Attribute) int {
	fmt.Println("start to callback")
	return 0
}

func errFunc(e error) int {
	fmt.Printf("error is %v", e)
	return 0
}

func main() {
	err := initIptable()
	if err != nil {
		fmt.Printf("init iptable error:%v", err)
		return
	}
	config := nflog.Config{
		Group:    100,
		Copymode: nflog.CopyPacket,
	}
	nf, err := nflog.Open(&config)
	if err != nil {
		fmt.Println("could not open nflog socket:", err)
		return
	}
	defer nf.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = nf.RegisterWithErrorFunc(ctx, callback, errFunc)
	//err = nf.Register(ctx, callback)
	if err != nil {
		fmt.Printf("register callback error:%v", err)
		return
	}
	<-ctx.Done()
}
