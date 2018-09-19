package main

import (
	"fmt"
	"syscall"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

/*
https://blog.heroku.com/applying-seccomp-filters-on-go-binaries?c=&utm_campaign=Newsletter_September_2018&utm_medium=email&utm_source=newsletter&utm_content=blog&utm_term=seccomp-filters
*/

func main() {
	//newDir()
	testeVariaveis()
}

func testeVariaveis() {
	var1 := "123"
	var2 := "456"
	var3 := var1 + var2
	fmt.Println(var3)
}

func newDir() {
	var syscalls = []string{
		"rt_sigaction", "mkdirat", "clone", "mmap", "readlinkat", "futex", "rt_sigprocmask",
		"mprotect", "write", "sigaltstack", "gettid", "read", "open", "close", "fstat", "munmap",
		"brk", "access", "execve", "getrlimit", "arch_prctl", "sched_getaffinity", "set_tid_address", "set_robust_list"}
	whiteList(syscalls)

	err := syscall.Mkdir("/tmp/moo", 0755)
	if err != nil {
		panic(err)
	} else {
		fmt.Printf("I just created a file\n")
	}

	err2 := syscall.Exec("/bin/ls", []string{"ls", "-l"}, nil)

	if err2 != nil {
		panic(err2)
	} else {
		fmt.Printf("erro2 ok\n")
	}
}

func whiteList(syscalls []string) {

	filter, err := libseccomp.NewFilter(libseccomp.ActErrno.SetReturnCode(int16(syscall.EPERM)))
	if err != nil {
		fmt.Printf("Error creating filter: %s\n", err)
	}
	for _, element := range syscalls {
		fmt.Printf("[+] Whitelisting: %s\n", element)
		syscallID, err := libseccomp.GetSyscallFromName(element)
		if err != nil {
			panic(err)
		}
		filter.AddRule(syscallID, libseccomp.ActAllow)
	}
	filter.Load()
}
