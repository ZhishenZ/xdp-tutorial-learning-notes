# XDP tutorials

## Related Works

https://hackmd.io/@0xff07/network/https%3A%2F%2Fhackmd.io%2F%400xff07%2FHJe-We22F

http://arthurchiao.art/blog/bpf-advanced-notes-2-zh/

https://docs.cilium.io/en/stable/bpf/progtypes/



## Data Link Layer Operation

XDP programs are executed in the kernel at the data link layer (Layer 2) of the network stack. XDP is specifically designed to operate at the data link layer to process packets as they enter or exit a network interface.

The C program containing the XDP code is a kernel-level program that processes network packets at the data link layer (Layer 2) and performs actions like filtering, forwarding, or modification based on the content of the packet headers, such as Ethernet, IP, TCP, or UDP headers.

## xdp data structure

```c
struct xdp_rxq_info {
	struct net_device *dev;
	u32 queue_index;
	u32 reg_state;
	struct xdp_mem_info mem;
	unsigned int napi_id;
	u32 frag_size;
} ____cacheline_aligned; /* perf critical, avoid false-sharing */

struct xdp_txq_info {
	struct net_device *dev;
};

enum xdp_buff_flags {
	XDP_FLAGS_HAS_FRAGS		= BIT(0), /* non-linear xdp buff */
	XDP_FLAGS_FRAGS_PF_MEMALLOC	= BIT(1), /* xdp paged memory is under
						   * pressure
						   */
};

struct xdp_buff {
	void *data;
	void *data_end;
	void *data_meta;
	void *data_hard_start;
	struct xdp_rxq_info *rxq;
	struct xdp_txq_info *txq;
	u32 frame_sz; /* frame size to deduce data_hard_end/reserved tailroom*/
	u32 flags; /* supported values defined in xdp_buff_flags */
};
```



In `bpf.h` header file

```c
enum xdp_action {
        XDP_ABORTED = 0,
        XDP_DROP,
        XDP_PASS,
        XDP_TX,
        XDP_REDIRECT,
};
```





## How is XDP related with eBPF?

XDP program is called by the `bpf()` system call with the `bpf_prog_type` `BPF_PROG_TYPE_XDP`



## tutorial 1

### look into the BPF-ELF object

after compilaton

`llvm-objdump -S xdp_pass_kern.o`

```
xdp_pass_kern.o:	file format ELF64-BPF

Disassembly of section xdp:
xdp_prog_simple:
; {
       0:	b7 00 00 00 02 00 00 00 	r0 = 2
; return XDP_PASS;
       1:	95 00 00 00 00 00 00 00 	exit
```

- `llvm-objdump` is a command-line tool that is used to disassemble object files and display the assembly code for each section of the file.
- The `-S` option tells `llvm-objdump` to display the assembly code for each section of the object file.
- `xdp_pass_kern.o` is the name of the object file that you want to disassemble.

The sequence of bytes `b7 00 00 00 02 00 00 00` is a BPF bytecode instruction that sets the value of register `r0` to the constant value 2.

Here's how to break down the instruction:

- `b7`: This byte is the opcode for the `MOV` (move) instruction. The `MOV` instruction is used to move data between registers and memory.
- `00 00 00 02`: These four bytes represent the 32-bit constant value 2 that will be moved into `r0`.
- `00 00 00`: These three bytes are padding to align the instruction to a 64-bit word.




The sequence of bytes `95 00 00 00 00 00 00 00` is a BPF bytecode instruction that terminates the program and returns control to the caller.

Here's how to break down the instruction:

- `95`: This byte is the opcode for the `EXIT` instruction. The `EXIT` instruction is used to terminate the program.
- `00 00 00 00 00 00 00`: These seven bytes are padding to align the instruction to a 64-bit word.



`.o` file is a ELF file.



### Loading and the XDP hook

The BPF byte code is stored in an ELF file. To load this into the kernel, user space needs an ELF loader to read the file and pass it into the kernel int the right format.

The C code in [xdp_pass_user.c](https://github.com/xdp-project/xdp-tutorial/blob/master/basic01-xdp-pass/xdp_pass_user.c) shows how to write a BPF loader specifically for our `xdp_pass_kern.o` ELF file. This loader attaches the program in the ELF file to an XDP hook on a network device. It does seem overkill to write a C program to simply load and attach a specific BPF-program. However, we still include this in the tutorial since it will help you integrate BPF into other Open Source projects.

There are some alternatives to writing a new loader:

- The standard iproute2 tool
- The xdp-loader from xdp-tools

#### loading via iproute2 `ip`

```c
sudo ip link set dev lo xdpgeneric obj xdp_pass_kern.o sec xdp
```

The command attaches an XDP program to the loopback interface (`lo`) on the local system.

- `sudo`: This is a command that runs the following command with administrative privileges.
- `ip link set dev lo xdpgeneric`:  `link` specifies that the command should operate on a network interface. The `set` specifies that the command should modify the configuration of the specified network interface. The `dev` parameter specifies the network interface to be modified, which in this case is the loopback interface (`lo`). The `xdpgeneric` keyword indicates that an XDP program should be attached to the interface. The generic XDP hook is a flexible and dynamic way to attach XDP programs to network interfaces, without the need for complex kernel module configurations or system restarts.
- `obj xdp_pass_kern.o`: This specifies the object file (`xdp_pass_kern.o`) that contains the compiled XDP program code.
- `sec xdp`: This specifies the section (`xdp`) of the object file that contains the XDP program. The `xdp` section is used to indicate to the BPF loader that this is a valid XDP program that should be attached to the specified network interface.

Listing the device via `ip link show` also shows the XDP info:

```
$ ip link show dev lo
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 xdpgeneric qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    prog/xdp id name xdp_prog_simple 220 tag 3b185187f1855c4c jited
```

Removing the XDP program again from the device:

```
ip link set dev lo xdpgeneric off
```

#### loading via xdp-loader

first `cd` to the xdp-tools library

and then compile the `xdp-loader` tool

```c
make
```

and then install the `xdp-loader` tool:

```c
sudo make install
```

then the `xdp-loader` is installed as a tool.



**load** the `xdp_pass_kern.o` file

```c
$ sudo xdp-loader load -m skb lo xdp_pass_kern.o
```

and then we can check the loaded XDP program by

```c
$ sudo xdp-loader status
CURRENT XDP PROGRAM STATUS:

Interface        Prio  Program name      Mode     ID   Tag               Chain actions
--------------------------------------------------------------------------------------
lo                     xdp_dispatcher    skb      108  90f686eb86991928
 =>              50     xdp_prog_simple           117  3b185187f1855c4c  XDP_PASS
ksb                    <No XDP program loaded!>
kli                    <No XDP program loaded!>
koni                   <No XDP program loaded!>
bridge_windows         <No XDP program loaded!>
tap_windows            <No XDP program loaded!>
kli_it                 <No XDP program loaded!>
ksi                    <No XDP program loaded!>
krc_net                <No XDP program loaded!>
ksb_ifb                <No XDP program loaded!>
koi_ecat               <No XDP program loaded!>
cpub                   <No XDP program loaded!>
```



**unload the program** via xdp-loader

by the XDP's ID

```c
kuka@infallible-hawking ~/xdp-tutorial/basic01-xdp-pass $ sudo xdp-loader unload lo -i 98
```

or we can simply unload all the XDP programs on the interface

```c
kuka@infallible-hawking ~/xdp-tutorial/basic01-xdp-pass $ sudo xdp-loader unload lo -a
```



#### loading via the c program in the repo

To load the program using our own loader, issue this command:

```
$ sudo ./xdp_pass_user --dev lo
Success: Loading XDP prog name:xdp_prog_simple(id:732) on device:lo(ifindex:1)
```

Loading the program again will add a second program instance to the XDP dispatcher on the interface.

```
$ sudo ./xdp_pass_user -d lo
Success: Loading XDP prog name:xdp_prog_simple(id:745) on device:lo(ifindex:1)

$ xdp-loader status lo
CURRENT XDP PROGRAM STATUS:

Interface        Prio  Program name      Mode     ID   Tag               Chain actions
--------------------------------------------------------------------------------------
lo                     xdp_dispatcher    skb      738  94d5f00c20184d17
 =>              50     xdp_prog_simple           732  3b185187f1855c4c  XDP_PASS
 =>              50     xdp_prog_simple           745  3b185187f1855c4c  XDP_PASS
```

You can list XDP programs on the device using different commands, and verify that the program ID is the same:

- `ip link list dev lo`
- `bpftool net list dev lo`
- `xdp-loader status lo`

**Unloading using `xdp_pass_user`**

To unload the program using our own loader, use this command, with the `id` of the program to unload:

```
$ sudo ./xdp_pass_user --dev lo -U 745
Detaching XDP program with ID 745 from lo
Success: Unloading XDP prog name: xdp_prog_simple
```

You can also unload all programs from the XDP hook on hte device using this command:

```
$ ./xdp_pass_user --dev lo --unload-all
```



## The `ip link` command

The `ip link` command is a Linux command that is used to display and manage network interfaces.

When used with no options, the `ip link` command displays a list of all network interfaces on the system, along with their current state (up or down), MAC address, and other information.

The `ip link` command can also be used to manage network interfaces. For example, it can be used to bring an interface up or down, change its MAC address, set its MTU, and more.

Here are some examples of how the `ip link` command can be used:

- `ip link show`: Displays a list of all network interfaces on the system

- `ip link set dev eth0 up`: Brings the `eth0` network interface up
  for example on our KRC5 system

  ```c
  kuka@infallible-hawking ~ $ sudo ip link set dev koni down
  ```

  and then check by `ip link`

  ```
  ...
  5: koni: <BROADCAST,MULTICAST> mtu 1500 qdisc mq state DOWN mode DEFAULT group default qlen 1000
      link/ether 00:60:c8:06:76:31 brd ff:ff:ff:ff:ff:ff
  ...
  ```

  and then set it up again

  ```c
  kuka@infallible-hawking ~ $ sudo ip link set dev koni up
  ```

  and then check by `ip link`

  ```
  ...
  5: koni: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc mq state DOWN mode DEFAULT group default qlen 1000
      link/ether 00:60:c8:06:76:31 brd ff:ff:ff:ff:ff:ff
  ...
  ```



- `ip link set dev eth0 down`: Brings the `eth0` network interface down

- `ip link set dev eth0 address 00:11:22:33:44:55`: Sets the MAC address of the `eth0` network interface to `00:11:22:33:44:55`

- `ip link set dev eth0 mtu 1500`: Sets the MTU of the `eth0` network interface to `1500`



## Setup environment



### create a shell alias for easy use of script from anywhere `eval $(./testenv.sh alias)`

### delete a test envrionment

```c
kuka@infallible-hawking /run $ sudo ip netns list
test (id: 0)
kuka@infallible-hawking /run $ sudo ip netns delete test
```



or use the integrated tool `t`

```sh
t teardown test01
```

and we can from inside of the test environment

```
t ping
```



## tutorial 2

Set up an environment:

First create a alias of the script

```c
eval $(./testenv.sh alias)
```

and then create an environment for this tutorial

````c
t setup --name veth-basic02
````

we can again check the content of the assembly file

```c
llvm-objdump -S xdp_prog_kern.o
```



```c
kuka@infallible-hawking ~/xdp-tutorial/basic02-prog-by-name (master) $ llvm-objdump -S xdp_prog_kern.o

xdp_prog_kern.o:        file format elf64-bpf

Disassembly of section xdp:

0000000000000000 <xdp_pass_func>:
;       return XDP_PASS;
       0:       b7 00 00 00 02 00 00 00 r0 = 2
       1:       95 00 00 00 00 00 00 00 exit

0000000000000010 <xdp_drop_func>:
;       return XDP_DROP;
       2:       b7 00 00 00 01 00 00 00 r0 = 1
       3:       95 00 00 00 00 00 00 00 exit
```



Check the xdp-loader status

```c
sudo xdp-loader status
```

if we need to unload the port

```c
sudo xdp-loader unload lo -a
```

load the filter program into the created environment

```c
$ sudo ./xdp_loader --dev veth-basic02 --progname xdp_drop_func
```

and then check the local ip of the created envrionment by the following command which is `fc00:dead:cafe:1::1`

```c
$ ip a
...
14: cpub: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 8174 qdisc pfifo_fast state UNKNOWN group default qlen 1000
    link/ether 02:60:c8:00:00:01 brd ff:ff:ff:ff:ff:ff
    inet 192.168.0.1/24 brd 192.168.0.255 scope global cpub
       valid_lft forever preferred_lft forever
15: veth-basic02@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdp/id:58 qdisc noqueue state UP group default qlen 1000
    link/ether b6:7a:b3:59:ff:fe brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fc00:dead:cafe:1::1/64 scope global
       valid_lft forever preferred_lft forever
    inet6 fe80::b47a:b3ff:fe59:fffe/64 scope link
       valid_lft forever preferred_lft forever
```

to test if the **drop** filter is loaded in the test environment

```c
kuka@infallible-hawking ~/xdp-tutorial/basic02-prog-by-name (master*) $ t enter
```

ping the port

```c
infallible-hawking basic02-prog-by-name (master*) # ping sudo ./xdp_loader --dev veth-basic02 --unload-all
PING fc00:dead:cafe:1::1(fc00:dead:cafe:1::1) 56 data bytes
^C
--- fc00:dead:cafe:1::1 ping statistics ---
14 packets transmitted, 0 received, 100% packet loss, time 13309ms
```



### `::` in IPv6

In the case of `::`, it is equivalent to one or more segments of `0`, depending on the number of segments required to fill the remaining space in the 128-bit address. For example, `::` is equivalent to `0:0:0:0:0:0:0:0`, while `::1` is equivalent to `0:0:0:0:0:0:0:1`, and `2001:0db8::` is equivalent to `2001:0db8:0:0:0:0:0:0`.

### Here are some example commands:

```
sudo ./xdp_loader --help
sudo ./xdp_loader --dev veth-basic02
sudo ./xdp_loader --dev veth-basic02 --unload-all
sudo ./xdp_loader --dev veth-basic02 --progname xdp_drop_func
sudo ./xdp_loader --dev veth-basic02 --progname xdp_pass_func
sudo ./xdp_loader --dev veth-basic02 --progname xdp_aborted_func
```

XDP_ABORTED is different from XDP_DROP, because it triggers the tracepoint named `xdp:xdp_exception`.

While pinging from inside the namespace, record this tracepoint and observe these records. E.g with perf like this:

```
sudo perf record -a -e xdp:xdp_exception sleep 4
sudo perf script
```



## BPF maps tutorial 3

BPF maps is a persistent mechanism available to BPF programs.

BPF map is accessible from kernel side and also the user space.



```c
kuka@infallible-hawking ~/xdp-tutorial/basic03-map-counter (master*) $ sudo ./xdp_load_and_stats --dev veth-basic02
```

and then start another terminal and ping the network environment.

Then you see some network packages transport here:

```c
Success: Loaded BPF-object(xdp_prog_kern.o) and used section(xdp_stats1_func)
 - XDP prog id:240 attached on device:veth-basic02(ifindex:15)

Collecting stats from BPF map
 - BPF map (bpf_map_type:2) id:53 name:xdp_stats_map key_size:4 value_size:8 max_entries:5

XDP-action
XDP_PASS               0 pkts (         0 pps) period:0.250153
XDP_PASS               0 pkts (         0 pps) period:2.000173
XDP_PASS               0 pkts (         0 pps) period:2.000166
XDP_PASS               0 pkts (         0 pps) period:2.000169
XDP_PASS               0 pkts (         0 pps) period:2.000173
XDP_PASS               0 pkts (         0 pps) period:2.000171
XDP_PASS               0 pkts (         0 pps) period:2.000169
XDP_PASS               1 pkts (         0 pps) period:2.000167
XDP_PASS               3 pkts (         1 pps) period:2.000169
XDP_PASS               5 pkts (         1 pps) period:2.000166
XDP_PASS               7 pkts (         1 pps) period:2.000173
XDP_PASS               9 pkts (         1 pps) period:2.000119
XDP_PASS              10 pkts (         0 pps) period:2.000116
XDP_PASS              12 pkts (         1 pps) period:2.000157
XDP_PASS              14 pkts (         1 pps) period:2.000170
XDP_PASS              16 pkts (         1 pps) period:2.000171
XDP_PASS              16 pkts (         0 pps) period:2.000095
```



## What is a Hook point?



A hook point is a specific location in the Linux kernel's networking stack where a BPF program can be attached to perform a specific task.

For example, a BPF program can be attached to a hook point in the kernel's networking stack to intercept and filter incoming packets based on certain criteria (such as the packet's source or destination address). The BPF program can then either drop the packet or allow it to continue on its path through the network stack.



The kernel supports different eBPF programs. These programs can be attached to different hook points

![img](http://arthurchiao.art/assets/img/socket-acceleration-with-ebpf/bpf-kernel-hooks.png)

When an event related to these hooks is triggered in the kernel (for example, the `setsockopt()` system call occurs), the BPF program attached here will be executed.









 One hook position as example



```c
static inline int sock_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	return sock_queue_rcv_skb_reason(sk, skb, NULL);
}

int sock_queue_rcv_skb_reason(struct sock *sk, struct sk_buff *skb,
			      enum skb_drop_reason *reason)
{
	enum skb_drop_reason drop_reason;
	int err;

	err = sk_filter(sk, skb);
	if (err) {
		drop_reason = SKB_DROP_REASON_SOCKET_FILTER;
		goto out;
	}
	err = __sock_queue_rcv_skb(sk, skb);
	switch (err) {
	case -ENOMEM:
		drop_reason = SKB_DROP_REASON_SOCKET_RCVBUFF;
		break;
	case -ENOBUFS:
		drop_reason = SKB_DROP_REASON_PROTO_MEM;
		break;
	default:
		drop_reason = SKB_NOT_DROPPED_YET;
		break;
	}
out:
	if (reason)
		*reason = drop_reason;
	return err;
}
EXPORT_SYMBOL(sock_queue_rcv_skb_reason);
```



in `filter.c` and  `filter.h`

```c
static inline int sk_filter(struct sock *sk, struct sk_buff *skb)
{
	return sk_filter_trim_cap(sk, skb, 1);
}

int sk_filter_trim_cap(struct sock *sk, struct sk_buff *skb, unsigned int cap)
{
	int err;
	struct sk_filter *filter;

	/*
	 * If the skb was allocated from pfmemalloc reserves, only
	 * allow SOCK_MEMALLOC sockets to use it as this socket is
	 * helping free memory
	 */
	if (skb_pfmemalloc(skb) && !sock_flag(sk, SOCK_MEMALLOC)) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_PFMEMALLOCDROP);
		return -ENOMEM;
	}
	err = BPF_CGROUP_RUN_PROG_INET_INGRESS(sk, skb);
	if (err)
		return err;

	err = security_sock_rcv_skb(sk, skb);
	if (err)
		return err;

	rcu_read_lock();
	filter = rcu_dereference(sk->sk_filter);
	if (filter) {
		struct sock *save_sk = skb->sk;
		unsigned int pkt_len;

		skb->sk = sk;
		pkt_len = bpf_prog_run_save_cb(filter->prog, skb);
		skb->sk = save_sk;
		err = pkt_len ? pskb_trim(skb, max(cap, pkt_len)) : -EPERM;
	}
	rcu_read_unlock();

	return err;
}
EXPORT_SYMBOL(sk_filter_trim_cap);
```



skb means socket buffer



## Why do we need a BPF Map?

http://arthurchiao.art/blog/bpf-advanced-notes-2-zh/

BPF maps are used for XDP packet transferring because they allow for the sharing of data between the eBPF program running on the kernel and user space applications. This is important because XDP runs in the kernel and does not have direct access to user space. By using BPF maps, the XDP program can pass data to user space, where it can be processed or stored. Additionally, BPF maps can be used to store and share state information between different instances of the XDP program, allowing for more efficient packet processing and filtering.



## XDP redirection



XDP redirect is a technique used in the Linux kernel for fast and efficient packet processing. With XDP redirect, incoming packets can be redirected from the network interface to a user-defined program, without having to copy the packet data into user space. Instead, the packet is processed within the kernel using an eBPF program, and then sent directly to its destination.

XDP redirect is useful for a variety of applications, such as packet filtering, load balancing, and traffic analysis. It is particularly well-suited for high-speed networks, where the overhead of copying packets into user space can become a bottleneck.

One of the key benefits of XDP redirect is its ability to offload packet processing from the CPU to the network interface card (NIC), using hardware acceleration. This allows for faster packet processing and lower latency, which can be critical in high-performance networking applications.

### `XDP_REDIRECT`

`XDP_REDIRECT` is one of the possible return values for an XDP hook, which allows the eBPF program to redirect the packet to a different network interface for further processing. This is done by specifying the index of the output interface in the `ctx->ingress_ifindex` field of the XDP context.

When the `XDP_REDIRECT` action is used, the packet is not forwarded to the upper networking layers of the kernel, but instead is redirected to the specified network interface for further processing.



One example

`BPF_MAP_TYPE_CPUMAP` can redirect the packet to a specific CPU.

Setup new environment named “test”: `./testenv.sh setup --name=test`

Create a shell alias for easy use of script from anywhere: `eval $(./testenv.sh alias)`


Do not change the debugging config with the following command
```c
echo 'CFLAGS += -O0 -DHAVE_ELF' `${PKG_CONFIG} libelf --cflags` >> $CONFIG
```



Change the debugging config

```c
{
    "configurations": [
        {
            "name": "(gdb) Launch",
            "type": "cppdbg",
            "request": "launch",
            "program": "/home/clemens/KUKA/xdp-tutorial/basic04-pinning-maps/xdp_loader",
            "args": ["-d", "test4", "--progname", "xdp_pass_func"],
            "stopAtEntry": false,
            "cwd": "/home/clemens/KUKA/xdp-tutorial/basic04-pinning-maps",
            "environment": [],
            "externalConsole": false,
            "miDebuggerServerAddress":"127.0.0.1:5556",
            "MIMode": "gdb",
            "setupCommands": [
                {
                    "description": "Enable pretty-printing for gdb",
                    "text": "-enable-pretty-printing",
                    "ignoreFailures": true
                },
                {
                    "description": "Set Disassembly Flavor to Intel",
                    "text": "-gdb-set disassembly-flavor intel",
                    "ignoreFailures": true
                }
            ]
        }
    ],
    "version": "2.0.0"
}
```











```
xdp-loader load -m skb lo xdp_prog_kern.o
```



```
sudo ./xdp-loader load -m skb lo xdp_prog_kern.o
```





to check if the bpf system is already mounted, use `mount` in the terminal command line.







```c
sudo ./xdp_loader --dev aa --progname xdp_drop_func
```



unload all

```c
sudo ./xdp_loader --dev aa --unload-all
```





The solution

https://github.com/xdp-project/xdp-tutorial/pull/57/files

## Tutorial 4

Here we use two separate programs. The first one `xdp_loader.c` is the file that loads the *XDP* program into the kernel. The second program ` xdp_stats.c` prints the statistics from the BPF map, which is a user space application.

### Pinning Mechanism

The mechanism used for sharing BPF maps between programs is called *pinning*. What this means is that we create a file for each map under a special file system mounted at `/sys/fs/bpf/`.

The needed mount command is

```c
mount -t bpf bpf /sys/fs/bpf
```



## Tutorial 5 , packet



### HOW TO

The documentation of this tutorial is like a shit. With a lot of trying around. I found out the way to load the program.





Copy the `xdp_loader` from the `/basic04-pinning-maps` directory.

First open a new environment named `test`

```sh
sudo ./xdp_loader --dev test --progname xdp_parser_func
```

I do not really understand what the loader did. The important thing is that this message shows up `Success: Loaded BPF-object(xdp_prog_kern.o) and used program(xdp_parser_func)` I just simply ignored the other programs.

```sh
(base) clemens@ThinkPad-P15s:~/KUKA/xdp-tutorial/packet01-parsing$ sudo ./xdp_loader --dev test --progname xdp_parser_func
libbpf: elf: skipping unrecognized data section(7) xdp_metadata
libbpf: prog 'xdp_pass': BPF program load failed: Invalid argument
libbpf: prog 'xdp_pass': failed to load: -22
libbpf: failed to load object 'xdp-dispatcher.o'
libbpf: elf: skipping unrecognized data section(7) xdp_metadata
libbpf: prog 'xdp_dispatcher': BPF program load failed: Invalid argument
libbpf: prog 'xdp_dispatcher': -- BEGIN PROG LOAD LOG --
Func#11 is safe for any args that match its prototype
btf_vmlinux is malformed
R1 type=ctx expected=fp
; int xdp_dispatcher(struct xdp_md *ctx)
0: (bf) r6 = r1
1: (b7) r0 = 2
; __u8 num_progs_enabled = conf.num_progs_enabled;
2: (18) r8 = 0xffff8ee3e5f09b10
4: (71) r7 = *(u8 *)(r8 +2)
 R0_w=invP2 R1=ctx(id=0,off=0,imm=0) R6_w=ctx(id=0,off=0,imm=0) R8_w=map_value(id=0,off=0,ks=4,vs=124,imm=0) R10=fp0
; if (num_progs_enabled < 1)
5: (15) if r7 == 0x0 goto pc+141
; ret = prog0(ctx);
6: (bf) r1 = r6
7: (85) call pc+140
btf_vmlinux is malformed
R1 type=ctx expected=fp
Caller passes invalid args into func#1
processed 84 insns (limit 1000000) max_states_per_insn 0 total_states 9 peak_states 9 mark_read 1
-- END PROG LOAD LOG --
libbpf: prog 'xdp_dispatcher': failed to load: -22
libbpf: failed to load object 'xdp-dispatcher.o'
libxdp: Failed to load dispatcher: Invalid argument
libxdp: Falling back to loading single prog without dispatcher
libbpf: elf: skipping unrecognized data section(7) xdp_metadata
libbpf: prog 'xdp_pass': BPF program load failed: Invalid argument
libbpf: prog 'xdp_pass': failed to load: -22
libbpf: failed to load object 'xdp-dispatcher.o'
Success: Loaded BPF-object(xdp_prog_kern.o) and used program(xdp_parser_func)
 - XDP prog attached on device:test(ifindex:24)
 - Unpinning (remove) prev maps in /sys/fs/bpf/test/
 - Pinning maps in /sys/fs/bpf/test/
```







and then in the other terminal

```sh
(base) clemens@ThinkPad-P15s:~/KUKA/xdp-tutorial/basic04-pinning-maps$
sudo ./xdp_stats -d test
```

The `xdp_stats` is in the `/basic04-pinning-maps` because the`xdp_stats` program in this directory some how does not work.



Then

```sh
ping t
```

to see if the network packet parsing work.



#### unload the XDP program

`cd` to the second basic tutorial and

```sh
(base) clemens@ThinkPad-P15s:~/KUKA/xdp-tutorial/basic02-prog-by-name$ sudo ./xdp_loader --dev test --unload-all
Success: Unloading XDP prog name: xdp_pass_func
```

to unload the program. But don’t ask me why this one work but the others not.





### Parser functions

In networking, parser functions are used to dissect and interpret data packets or frames. For example, in the case of the internet protocol suite, parser functions extract information from headers like Ethernet, IP, TCP, UDP, etc., to route, forward, or process network traffic.

The purpose of the Byte-count bounds check in the `parse_ethhdr` function, as written in the provided code, is to provide a safety mechanism in case of an unexpected scenario where the incoming packet's data buffer is shorter than expected or if there is some issue with the data buffer that could lead to accessing memory outside its bounds.

### Header Cursor

```c
static __always_inline int parse_ethhdr_vlan(struct hdr_cursor *nh,
                                             ... ) {
int hdrsize = sizeof(*eth);
if (nh->pos + hdrsize > data_end)
    return -1;
```

The header cursor tracks the current parsing position when going through a packet and parsing subsequent headers.

### return code of the XDP action

| Struct            | Header file          |
| ----------------- | -------------------- |
| `struct ethhdr`   | `<linux/if_ether.h>` |
| `struct ipv6hdr`  | `<linux/ipv6.h>`     |
| `struct iphdr`    | `<linux/ip.h>`       |
| `struct icmp6hdr` | `<linux/icmpv6.h>`   |
| `struct icmphdr`  | `<linux/icmp.h>`     |







### inline function

A function is marked as "inline," the compiler will replace the function call with the actual code of the function at the location where the function is called. This process is known as "inlining." Instead of jumping to the function's code through a function call, the compiler directly inserts the function's code at the call site.

Because eBPF programs only have limited support for function calls, helper functions need to be inlined into the main function. The `__always_inline` marker on the function definition ensures this.

Adding the `#pragma unroll` statement on the line before the loop, and only works with loops where the number of iterations are known at compile time.

#### The ICMP6H

It indicates the specific purpose or functionality of the ICMPv6 message. For example:

- `ICMPv6_ECHO_REQUEST` (Type 128): Represents an Echo Request message, used for the "ping" functionality in IPv6 networks. It is sent to check the reachability and responsiveness of a remote node.
- `ICMPv6_ECHO_REPLY` (Type 129): Represents an Echo Reply message, sent as a response to an Echo Request message.



**icmp6_sequence**

```c
if (bpf_ntohs(icmp6h->icmp6_sequence) % 2 == 0)
	action = XDP_DROP;
```

`icmp6_sequence` is the sequence number in ICMPv6 (Internet Control Message Protocol version 6). The sequence number in the `ping` command is a unique identifier assigned to each ICMP Echo Request packet. It starts at 0 or 1 and increments for each subsequent packet sent.

**What is a ICMP6H Sequence Number?**

Typically, the ICMPv6 Sequence Number starts at 0 and increments by 1 for each new Echo Request message.

### VLAN Assignment howto

Firstly run the command `t ping --vlan test` and load the program as in the *HOW TO* section

First open a new environment named `test`

```sh
sudo ./xdp_loader --dev test --progname xdp_parser_func
```

and then in the other terminal

```sh
(base) clemens@ThinkPad-P15s:~/KUKA/xdp-tutorial/basic04-pinning-maps$
sudo ./xdp_stats -d test
```

**check if the function is loaded**

```sh
(base) clemens@ThinkPad-P15s:~/KUKA/xdp-tutorial/packet01-parsing$ sudo ./xdp-loader status
CURRENT XDP PROGRAM STATUS:

Interface        Prio  Program name      Mode     ID   Tag               Chain actions
--------------------------------------------------------------------------------------
lo                     <No XDP program loaded!>
enp0s31f6              <No XDP program loaded!>
wlp0s20f3              <No XDP program loaded!>
br-fd0e07786ceb        <No XDP program loaded!>
docker0                <No XDP program loaded!>
br-b1ca545181aa        <No XDP program loaded!>
enx605b302ad1b6        <No XDP program loaded!>
test                   xdp_parser_func   native   564  49ab3881a4f64d52
test.1                 <No XDP program loaded!>
test.2                 <No XDP program loaded!>
```

**Add a VLAN port**:

```sh
t reset --vlan
```

Check if the vlan ports are added:

```sh
24: test@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 86:d2:40:94:50:44 brd ff:ff:ff:ff:ff:ff link-netns test
    inet6 fc00:dead:cafe:3::1/64 scope global
       valid_lft forever preferred_lft forever
    inet6 fe80::84d2:40ff:fe94:5044/64 scope link
       valid_lft forever preferred_lft forever
25: test.1@test: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 86:d2:40:94:50:44 brd ff:ff:ff:ff:ff:ff
    inet6 fc00:dead:cafe:1003::1/64 scope global
       valid_lft forever preferred_lft forever
    inet6 fe80::84d2:40ff:fe94:5044/64 scope link
       valid_lft forever preferred_lft forever
26: test.2@test: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 86:d2:40:94:50:44 brd ff:ff:ff:ff:ff:ff
    inet6 fc00:dead:cafe:2003::1/64 scope global
       valid_lft forever preferred_lft forever
    inet6 fe80::84d2:40ff:fe94:5044/64 scope link
       valid_lft forever preferred_lft forever
```

We see that `test.1` and `test.2` are there and they are the added VLAN ports.



After adding the port, we can use the script command to ping the VLAN port (`test.1`) from the test environment. Thanks to the XDP programs, it parse the in the VLAN encapsulated IPV6 and let the half of the packages bypass.





load the XDP program into the kernel





why do we need to add the `vlan` checking part in to the function `parse_ethhdr_vlan()`?

If you do not include the VLAN parsing part (the `parse_ethhdr_vlan()` function) and you receive an Ethernet frame with VLAN tags, the return value of the function `parse_ethhdr` may not fulfill the condition `nh_type != bpf_htons(ETH_P_IPV6)` as expected.



### VLAN

the presence of a `@` symbol in the interface names is a common indicator that these interfaces are VLAN sub-interfaces.



To clarify, VLAN is a data link layer concept, and it involves adding an additional VLAN tag to Ethernet frames to logically segment a physical network into multiple virtual networks. The VLAN tagging process and VLAN handling occur at Layer 2, not Layer 1.



VLAN tagging is a feature of Ethernet frames, where a 4-byte tag is added to the Ethernet frame to identify the VLAN to which the frame the frame accordingly. This allows network administrator to create multiple logical networks over a single physical network network infrastructure, improving network performance, security, and manageability.



Here's an example of how a network packet with a VLAN tag is normally handled:

1. VLAN Tagging at the Source:
   - A network device (e.g., a computer or a server) generates a data packet and adds a VLAN tag to it. The VLAN tag includes information about the VLAN ID (VID) to which the packet belongs.
   - For example, if the device is in VLAN 10, the packet will be tagged with a VLAN ID of 10.
2. Packet Transmission:
   - The tagged packet is then sent to the network switch or router that is responsible for forwarding the packet to its destination.
3. Network Switch or Router Handling:
   - The network switch or router receives the packet and examines the VLAN tag.
   - Based on the VLAN tag, the switch/router determines the appropriate VLAN and forwards the packet to the corresponding VLAN interface (VLAN interface is associated with a specific VLAN).
   - For example, if the VLAN tag indicates VLAN ID 10, the packet will be forwarded to the VLAN interface associated with VLAN 10.
4. VLAN Segregation:
   - Once the packet is forwarded to the appropriate VLAN interface, it is segregated and treated as part of that VLAN.
   - The switch maintains separate forwarding tables for each VLAN, ensuring that packets are only forwarded to ports belonging to the same VLAN.
   - This isolation allows devices in different VLANs to communicate with each other only through a router, adding security and control to the network.
5. Packet Transmission to Destination:
   - The packet is then forwarded to the destination device(s) within the same VLAN.
6. VLAN Tag Removal at Destination:
   - If the receiving device is not VLAN-aware (e.g., an end-user device like a computer), it will process the packet as normal Ethernet traffic and remove the VLAN tag.

Here is a example of the VLAN header



Here's the example representation of an Ethernet frame with a VLAN tag:

```sh
pythonCopy code  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  Destination MAC Address (6 bytes)                          |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  Source MAC Address (6 bytes)                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |    VLAN Tag (4 bytes)                                        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  EtherType / Length (2 bytes) or LLC (3 bytes)               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                          Payload                              |
 |                             ...                               |
```



### EtherType Values

common EtherType values include:

- 0x0800: IPv4
- 0x86DD: IPv6
- 0x0806: ARP (Address Resolution Protocol)
- 0x8100: IEEE 802.1Q VLAN Tagged Frame (when VLAN tagging is used)









### why `!!`

The use of `!!` can sometimes be considered an explicit way to ensure that the result is treated as a boolean value (`1` or `0`)





### Adding IPv4 Support 



**First setup the IPv4 support**

```sh
(base) clemens@ThinkPad-P15s:~/KUKA/xdp-tutorial/testenv$ eval $(./testenv.sh alias)
WARNING: Creating sudo alias; be careful, this script WILL execute arbitrary programs
(base) clemens@ThinkPad-P15s:~/KUKA/xdp-tutorial/testenv$ t setup --legacy-ip
Setting up new environment 'xdptut-423c'
Setup environment 'xdptut-423c' with peer ip fc00:dead:cafe:1::2 and 10.11.1.2.
Waiting for interface configuration to settle...

Running ping from inside test environment:

PING fc00:dead:cafe:1::1(fc00:dead:cafe:1::1) 56 data bytes
64 bytes from fc00:dead:cafe:1::1: icmp_seq=1 ttl=64 time=0.024 ms

--- fc00:dead:cafe:1::1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.024/0.024/0.024/0.000 ms
```

And the new added test environment can be seen here: 

```sh
(base) clemens@ThinkPad-P15s:~$ ip a
...
8: xdptut-423c@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 0a:99:92:07:a5:08 brd ff:ff:ff:ff:ff:ff link-netns xdptut-423c
    inet 10.11.1.1/24 scope global xdptut-423c
       valid_lft forever preferred_lft forever
    inet6 fc00:dead:cafe:1::1/64 scope global 
       valid_lft forever preferred_lft forever
    inet6 fe80::899:92ff:fe07:a508/64 scope link 
       valid_lft forever preferred_lft forever
```

Firstly run the command `t ping --vlan test` and load the program as in the *HOW TO* section

First open a new environment named `test`

```sh
sudo ./xdp_loader --dev xdptut-423c --progname xdp_parser_func
```

check if the program is loaded 

```sh
(base) clemens@ThinkPad-P15s:~/KUKA/xdp-tutorial/packet01-parsing$ sudo ./xdp-loader status
CURRENT XDP PROGRAM STATUS:

Interface        Prio  Program name      Mode     ID   Tag               Chain actions
--------------------------------------------------------------------------------------
lo                     <No XDP program loaded!>
enp0s31f6              <No XDP program loaded!>
enx605b302ad1b6        <No XDP program loaded!>
wlp0s20f3              <No XDP program loaded!>
docker0                <No XDP program loaded!>
br-b1ca545181aa        <No XDP program loaded!>
br-fd0e07786ceb        <No XDP program loaded!>
xdptut-423c            xdp_parser_func   native   30   49ab3881a4f64d52 
```

 and `t ping --legacy-ip` to run a ping afterwards.

```sh
(base) clemens@ThinkPad-P15s:~/KUKA/xdp-tutorial/packet01-parsing$ t ping --legacy-ip
Running ping from inside test environment:

PING 10.11.1.1 (10.11.1.1) 56(84) bytes of data.
^C
--- 10.11.1.1 ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 1014ms
```





## Tutorial 6, Rewriting



Set up an environment:

First create a alias of the script

```c
eval $(./testenv.sh alias)
```

and then create an environment for this tutorial

````c
t setup --name test
````

First open a new environment named `test`

```sh
sudo ./xdp_loader --dev test --progname xdp_patch_ports_func
```

unload the program 

```
sudo ./xdp_loader --dev test --unload-all
```

The port number modified by XDP (eXpress Data Path) is the destination port number for sending data packets. In XDP, packet processing logic occurs along the path of packet reception and transmission.

`bpf_ntohs` is a BPF helper function that stands for **"Network to Host Order Short"**. It is used to convert the 16-bit unsigned short integer **(destination port number)** from network byte order (big-endian) to host byte order. `bpf_htons` is another BPF helper function that stands for "BPF Host to Network Order Short". It is used to convert the 16-bit unsigned short integer back to network byte order after the modification.



### Rewrite PORT number

The relationship between `tcpdump` and `socat` in the provided example is that they are used together to demonstrate the XDP program's functionality. The `tcpdump` command is used to capture and display network traffic on a specific network interface. The `socat` command acts as a packet generator that generates UDP packets to a specific destination on port 2000.



**Open two terminals**

in the first termimal

```sh
(base) clemens@ThinkPad-P15s:~/KUKA/xdp-tutorial/packet02-rewriting$ t exec -- socat - 'udp6:[fc00:dead:cafe:1::1]:2000'
```

and then in the second terminal 

```sh
(base) clemens@ThinkPad-P15s:~/KUKA/xdp-tutorial/testenv$ t tcpdump
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on test, link-type EN10MB (Ethernet), capture size 262144 bytes
```

in the first terminal with `socat` type something like a single character`a`.

And then in the other terminal the following will be shown up

```sh
(base) clemens@ThinkPad-P15s:~/KUKA/xdp-tutorial/testenv$ t tcpdump
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on test, link-type EN10MB (Ethernet), capture size 262144 bytes
16:55:31.176511 02:ba:c8:11:09:aa > be:cf:32:65:bd:ee, ethertype IPv6 (0x86dd), length 64: fc00:dead:cafe:1::2.35983 > fc00:dead:cafe:1::1.1999: UDP, length 2
16:55:31.176546 be:cf:32:65:bd:ee > 02:ba:c8:11:09:aa, ethertype IPv6 (0x86dd), length 112: fc00:dead:cafe:1::1 > fc00:dead:cafe:1::2: ICMP6, destination unreachable, unreachable port, fc00:dead:cafe:1::1 udp port 1999, length 58
```

It shows two different packets, one being the original UDP packet sent from `fc00:dead:cafe:1::2` to `fc00:dead:cafe:1::1` on port 1999, and the second being an **ICMPv6** "destination unreachable" message generated by the destination host in response to the UDP packet.

* `02:ba:c8:11:09:aa > be:cf:32:65:bd:ee`: The source MAC address (`02:ba:c8:11:09:aa`) sending the first packet to the destination (test environment interface) MAC address (`be:cf:32:65:bd:ee`).
* `fc00:dead:cafe:1::2.35983 > fc00:dead:cafe:1::1.1999`: The source IPv6 address (`fc00:dead:cafe:1::2`) with source UDP port `35983`, sending a UDP packet to the destination IPv6 address (`fc00:dead:cafe:1::1`) on destination UDP port `1999`.
* **we can see that the destination port is changed to `1999` by the loaded XDP program** 
* Then we can see that the destination port sent a response back to the source`be:cf:32:65:bd:ee > 02:ba:c8:11:09:aa`, which is an *unreachable* message. 



### Remove the outermost VLAN tag

Set up an environment:

First create a alias of the script

```c
eval $(./testenv.sh alias)
```

and then create an environment for this tutorial

````c
t setup --name test
````

First we want to show how does it look like without the VLAN removing mechanism  

```sh
t reset --vlan
```



First in the current added environment

```sh
(base) clemens@ThinkPad-P15s:~/KUKA/xdp-tutorial/packet02-rewriting$ t reset --vlan
Tearing down environment 'test'
rmdir: failed to remove '/sys/fs/bpf/test': Directory not empty
Setting up new environment 'test'
Setup environment 'test' with peer ip fc00:dead:cafe:1::2.
Waiting for interface configuration to settle...

Running ping from inside test environment:

PING fc00:dead:cafe:1::1(fc00:dead:cafe:1::1) 56 data bytes
64 bytes from fc00:dead:cafe:1::1: icmp_seq=1 ttl=64 time=0.014 ms

--- fc00:dead:cafe:1::1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.014/0.014/0.014/0.000 ms
```

From one terminal, `ping` the sub-interface `test.1` from the environment. `test.1` is the receiver. 

```sh
(base) clemens@ThinkPad-P15s:~/KUKA/xdp-tutorial/packet02-rewriting$ t ping --vlan
Running ping from inside test environment:

PING fc00:dead:cafe:1001::1(fc00:dead:cafe:1001::1) 56 data bytes
64 bytes from fc00:dead:cafe:1001::1: icmp_seq=1 ttl=64 time=0.111 ms
64 bytes from fc00:dead:cafe:1001::1: icmp_seq=2 ttl=64 time=0.134 ms
^C
--- fc00:dead:cafe:1001::1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 2041ms
rtt min/avg/max/mdev = 0.111/0.143/0.186/0.031 ms
```

* Excursion: To better understand this, we can do something else to reach the same result. using
  ```sh
  (base) clemens@ThinkPad-P15s:~/KUKA/xdp-tutorial/packet02-rewriting$ t enter
  root@ThinkPad-P15s:/home/clemens/KUKA/xdp-tutorial/packet02-rewriting# ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: veth0@if11: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
      link/ether aa:fe:8d:de:a3:30 brd ff:ff:ff:ff:ff:ff link-netnsid 0
      inet6 fc00:dead:cafe:1::2/64 scope global 
         valid_lft forever preferred_lft forever
      inet6 fe80::a8fe:8dff:fede:a330/64 scope link 
         valid_lft forever preferred_lft forever
  3: veth0.1@veth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
      link/ether aa:fe:8d:de:a3:30 brd ff:ff:ff:ff:ff:ff
      inet6 fc00:dead:cafe:1001::2/64 scope global 
         valid_lft forever preferred_lft forever
      inet6 fe80::a8fe:8dff:fede:a330/64 scope link 
         valid_lft forever preferred_lft forever
  4: veth0.2@veth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
      link/ether aa:fe:8d:de:a3:30 brd ff:ff:ff:ff:ff:ff
      inet6 fc00:dead:cafe:2001::2/64 scope global 
         valid_lft forever preferred_lft forever
      inet6 fe80::a8fe:8dff:fede:a330/64 scope link 
         valid_lft forever preferred_lft forever
  ```

  and then ping the `test.1` port with the VLAN tag.
  ```sh
  root@ThinkPad-P15s:/home/clemens/KUKA/xdp-tutorial/packet02-rewriting# ping fc00:dead:cafe:1001::1
  ```

  

and in the other terminal 

```sh
(base) clemens@ThinkPad-P15s:~/KUKA/xdp-tutorial/testenv$ t tcpdump
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on test, link-type EN10MB (Ethernet), capture size 262144 bytes
09:43:41.457357 aa:fe:8d:de:a3:30 > 96:3a:32:d2:15:18, ethertype 802.1Q (0x8100), length 122: vlan 1, p 0, ethertype IPv6, fc00:dead:cafe:1001::2 > fc00:dead:cafe:1001::1: ICMP6, echo request, seq 2, length 64
09:43:41.457417 96:3a:32:d2:15:18 > aa:fe:8d:de:a3:30, ethertype 802.1Q (0x8100), length 122: vlan 1, p 0, ethertype IPv6, fc00:dead:cafe:1001::1 > fc00:dead:cafe:1001::2: ICMP6, echo reply, seq 2, length 64
09:43:42.481444 aa:fe:8d:de:a3:30 > 96:3a:32:d2:15:18, ethertype 802.1Q (0x8100), length 122: vlan 1, p 0, ethertype IPv6, fc00:dead:cafe:1001::2 > fc00:dead:cafe:1001::1: ICMP6, echo request, seq 3, length 64
09:43:42.481528 96:3a:32:d2:15:18 > aa:fe:8d:de:a3:30, ethertype 802.1Q (0x8100), length 122: vlan 1, p 0, ethertype IPv6, fc00:dead:cafe:1001::1 > fc00:dead:cafe:1001::2: ICMP6, echo reply, seq 3, length 64
^C
4 packets captured
4 packets received by filter
0 packets dropped by kernel
```

`vlan 1, p 0` indicates that the VLAN tag is present, and the VLAN ID is 1. The `p 0` part indicates the priority.



**Then, we load the XDP function into the network interface.**

load the program:

```sh
t reset --vlan
```

and load the program 

``` 
sudo ./xdp_loader --dev test --progname xdp_vlan_swap_func
```

The port number modified by the XDP program loaded on the `test.1` interface. 

unload the program

```
sudo ./xdp_loader --dev test --unload-all
```



In one terminal:

```sh
(base) clemens@ThinkPad-P15s:~/KUKA/xdp-tutorial/packet02-rewriting$ t ping --vlan
```

* which is equivalent to 
  ```sh
  (base) clemens@ThinkPad-P15s:~/KUKA/xdp-tutorial/packet02-rewriting$ t enter
  root@ThinkPad-P15s:/home/clemens/KUKA/xdp-tutorial/packet02-rewriting# ping fc00:dead:cafe:1001::1
  ```

In the other terminal:

```sh
(base) clemens@ThinkPad-P15s:~/KUKA/xdp-tutorial/testenv$ t tcpdump
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on test, link-type EN10MB (Ethernet), capture size 262144 bytes
14:20:42.921025 aa:fe:8d:de:a3:30 > 96:3a:32:d2:15:18, ethertype IPv6 (0x86dd), length 118: fc00:dead:cafe:1001::2 > fc00:dead:cafe:1001::1: ICMP6, echo request, seq 1, length 64
14:20:42.921052 96:3a:32:d2:15:18 > aa:fe:8d:de:a3:30, ethertype 802.1Q (0x8100), length 122: vlan 1, p 0, ethertype IPv6, fc00:dead:cafe:1001::1 > fc00:dead:cafe:1001::2: ICMP6, echo reply, seq 1, length 64
14:20:43.942312 aa:fe:8d:de:a3:30 > 96:3a:32:d2:15:18, ethertype IPv6 (0x86dd), length 118: fc00:dead:cafe:1001::2 > fc00:dead:cafe:1001::1: ICMP6, echo request, seq 2, length 64
14:20:43.942374 96:3a:32:d2:15:18 > aa:fe:8d:de:a3:30, ethertype 802.1Q (0x8100), length 122: vlan 1, p 0, ethertype IPv6, fc00:dead:cafe:1001::1 > fc00:dead:cafe:1001::2: ICMP6, echo reply, seq 2, length 64
^C
4 packets captured
4 packets received by filter
0 packets dropped by kernel
```

We see that, the incoming network traffic does not have any tag because it is popped by the XDP program `xdp_vlan_swap_func()`, but the echo replies will still have the *VLAN tags*. 



### insert a VLAN header into the Ethernet header



What does the function do:

![vlan_header](img/vlan_header.png)

https://en.wikipedia.org/wiki/File:Ethernet_802.1Q_Insert.svg



Interpretation of the code:

![add_vlan_header](img/add_vlan_header.jpg)







When `printf` encounters `%.*s`, it expects two arguments after the format string: the first argument is the width of the string to be printed (`width` in this case), and the second argument is the string to be printed (`str` in this case).





## Tutorial 7, Redirecting





### `XDP_TX`

The `XDP_TX` return value can be used to send the packet back from the same interface it came from. This functionality can be used to implement load balancers, to send simple ICMP replies, etc.



### `XDP_REDIRECT`

Besides the ability to transmit packets back from the same interface, there is an option to forward packets to egress ports of other interfaces. This can be done using the `bpf_redirect` or `bpf_redirect_map` helpers. These helpers will return the `XDP_REDIRECT` value. The `bpf_redirect` helper takes the interface index of the redirect port as parameter and may be used with other helpers such as `bpf_fib_lookup`. 



### Big Endian

Addresses within the IPv4/6 header are conventionally stored in big-endian byte order. 



### Checksum Implementation

When working with network packets or data structures that involve checksums, updating the checksum value directly after modifying the data can be computationally expensive, especially for large data chunks. Calculating the checksum for the entire modified data each time a change is made can introduce unnecessary overhead, especially in performance-sensitive contexts like networking.

This is where the concept of calculating the checksum difference comes into play. Instead of recomputing the checksum for the entire modified data, you can calculate the difference between the old and new checksum values based on the changes made. This difference can then be efficiently applied to the existing checksum value to obtain the updated checksum without needing to recompute it from scratch.







### Assign 1: Send packets back where they came from 

Here we need two interfaces.

* `veth0@if9` in the `test` environment 
* `test@if2` in the native environment

create the alias

```sh
$ eval $(./testenv.sh alias)
$ t setup -n test --legacy-ip
```

We **have to** load the interface within the virtual environment with the `xdp_pass_func` 

Because

> Note that in order to the transmit and/or redirect functionality to work, **all** involved devices should have an attached XDP program, including both veth peers.



Now we have two envrionments:

* Go into the `test` environment
  ```sh
  $ t enter test
  ```

  load the XDP program `xdp_pass_func`onto the `veth0` interface in the directory `/packet03-redirecting`
  ```sh
  $ ./xdp_loader --dev veth0 --progname xdp_pass_func
  ```

* In then load the redirecting program into the local `test` interface
   ```sh
   $ sudo ./xdp_loader --dev test --progname xdp_icmp_echo_func
   ```

* Start the `xdp_stats` program in one terminal
  ```sh
  $ sudo ./xdp_stats -d test
  ```

* And then start a`ping` command in the teminal
  ```sh 
  $ t ping --legacy-ip
  ```

  which pings the IP `10.11.1.1` from inside test environment 

* Then we can See there are packages retransmitted with the return value `XDP_TX`
  ```sh
  $ s
  udo ./xdp_stats -d test
  
  Collecting stats from BPF map
   - BPF map (bpf_map_type:6) id:27 name:xdp_stats_map key_size:4 value_size:16 max_entries:5
  XDP-action  
  XDP_ABORTED            0 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:0.250323
  XDP_DROP               0 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:0.250283
  XDP_PASS               0 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:0.250283
  XDP_TX                 2 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:0.250283
  XDP_REDIRECT           0 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:0.250284
  ```

* The result can also be observed by the `tcpdump` inside the `test`environment.
  ```sh
  (base) clemens@ThinkPad-P15s:~/KUKA/xdp-tutorial-learning-notes/testenv$ t enter test
  root@ThinkPad-P15s:/home/clemens/KUKA/xdp-tutorial-learning-notes/testenv# tcpdump
  tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
  listening on veth0, link-type EN10MB (Ethernet), capture size 262144 bytes
  ^C10:33:53.814915 IP 10.11.1.2 > 10.11.1.1: ICMP echo request, id 9757, seq 41, length 64
  10:33:53.814948 IP 10.11.1.1 > 10.11.1.2: ICMP echo reply, id 9757, seq 41, length 64
  10:33:54.816431 IP 10.11.1.2 > 10.11.1.1: ICMP echo request, id 9757, seq 42, length 64
  10:33:54.816465 IP 10.11.1.1 > 10.11.1.2: ICMP echo reply, id 9757, seq 42, length 64
  10:33:55.830849 IP 10.11.1.2 > 10.11.1.1: ICMP echo request, id 9757, seq 43, length 64
  10:33:55.830877 IP 10.11.1.1 > 10.11.1.2: ICMP echo reply, id 9757, seq 43, length 64
  10:33:56.854800 IP 10.11.1.2 > 10.11.1.1: ICMP echo request, id 9757, seq 44, length 64
  ```



### Assign 2: Redirect packets between two interfaces

This is how I understand how would this work:

1. We ping from the `Env 2` inside. A packet arrives at interface 1 from the external device ( `veth0` in `Env 1`). 
2. You have a BPF program that uses the `bpf_redirect` helper function to redirect the packet to interface `left@if2`. This involves updating the packet's metadata to indicate that it should be forwarded to interface `left@if2`.
3. interface `left@if2` sends the packet out to its intended destination.

We set up two interfaces

```sh
$ eval $(./testenv.sh alias)
$ t setup -n left --legacy-ip
$ t setup -n right --legacy-ip
```

The Setup should be 

```sh
Env 1                         Env 2
loaded with xdp_pass          loaded with xdp_redirect_func
----------------------        ----------------------
| veth0 in 1 (MAC=X2) |       | veth0 in 2 (MAC=Y2) |
| fc00:dead:cafe:1::2 |       | fc00:dead:cafe:2::2 |
----------||----------        ----------||----------
    left@if2 (MAC=X1)  <-------- right@if2 (MAC=Y1)
```



* load the interface`veth0` **inside** the `left` environment with the `xdp_pass` function.

  ```sh
  $ t enter -n left
  # ./xdp_loader --dev veth0 --progname xdp_pass_func
  ```

  check the IP of the left environment 
  ```sh
  # ip a
  ...
  2: veth0@if8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdp/id:80 qdisc noqueue state UP group default qlen 1000
      link/ether c2:01:56:b7:c8:b2 brd ff:ff:ff:ff:ff:ff link-netnsid 0
      inet 10.11.1.2/24 scope global veth0
         valid_lft forever preferred_lft forever
      inet6 fc00:dead:cafe:1::2/64 scope global 
         valid_lft forever preferred_lft forever
      inet6 fe80::c001:56ff:feb7:c8b2/64 scope link 
         valid_lft forever preferred_lft forever
  ```

  * write the mac address of the interface `veth0` in environment 2 into the XDP program in the `xdp_prog_kern.c`. 
  * change the value of the `ifindex` to be the `left@if2`.
  * then `make` the executable again. 

* load the redirecting program onto the `right` interface  

  ```sh
  $ sudo ./xdp_loader --dev right --progname xdp_redirect_func
  ```

  notice that it is easy to get mixed up with the  `progname`. make sure the program name is `xdp_redirect_func`

* enter the left environment and then observe the incoming network traffic. 

  ```sh
  $ t enter -n left
  ```

* In the other terminal enter the right environment and ping the `IPV6 Address` of the `env 1` form the `env 2` inside 
  ```sh
  $ t enter -n left
  # ping fc00:dead:cafe:1::2
  PING fc00:dead:cafe:1::2(fc00:dead:cafe:1::2) 56 data bytes
  ^C
  --- fc00:dead:cafe:1::2 ping statistics ---
  ```

* and then check the network packets recorded by `tcpdump`
  ```sh
  # tcpdump
  tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
  listening on veth0, link-type EN10MB (Ethernet), capture size 262144 bytes
  ^C17:25:38.713270 IP6 fc00:dead:cafe:2::2 > fc00:dead:cafe:1::2: ICMP6, echo request, seq 1, length 64
  17:25:38.713297 IP6 fc00:dead:cafe:1::2 > fc00:dead:cafe:2::2: ICMP6, echo reply, seq 1, length 64
  17:25:39.742385 IP6 fc00:dead:cafe:2::2 > fc00:dead:cafe:1::2: ICMP6, echo request, seq 2, length 64
  17:25:39.742429 IP6 fc00:dead:cafe:1::2 > fc00:dead:cafe:2::2: ICMP6, echo reply, seq 2, length 64
  17:25:40.766278 IP6 fc
  ```

We see that the it looks like there is a direct communication between the two environments `env 1` and `env 2`, although they are isolated from another. 

![XDP_BPF_redirect](img/XDP_BPF_redirect.jpg)



### Aissign 3: Bidirectional Router



#### Howto

We set up two interfaces

```sh
$ eval $(./testenv.sh alias)
$ t setup -n left --legacy-ip
$ t setup -n right --legacy-ip
```

then we load the `xdp_pass_func` for the inner interfaces after entering two virtual environments

```sh
$ t enter -n left
# ./xdp_loader --dev veth0 --progname xdp_pass_func
```

and 

```sh
$ t enter -n right
# ./xdp_loader --dev veth0 --progname xdp_pass_func
```

We then load the two XDP programs to the `left` and `right` interfaces

```sh
$ sudo ./xdp_loader --dev left --progname xdp_redirect_map_func
$ sudo ./xdp_loader --dev right --progname xdp_redirect_map_func
```

We register this bidirectional redirection by updating the BPF table by using the helper script

```sh
$ t redirect right left
```

> The `redirect` helpter program 

```c
populate_redirect_map()
{
    local src="$1"
    local dest="$2"
    local src_mac=$(ip netns exec $src cat /sys/class/net/veth0/address)
    local dest_mac=$(ip netns exec $dest cat /sys/class/net/veth0/address)

    # set bidirectional forwarding
    ./xdp_prog_user -d $src -r $dest --src-mac $src_mac --dest-mac $dest_mac
    ./xdp_prog_user -d $dest -r $src --src-mac $dest_mac --dest-mac $src_mac
}
```

> This section of code is setting up redirection rules for network traffic using XDP between two network namespaces. It queries the MAC addresses of the network interfaces within the namespaces and uses them as parameters when invoking the `xdp_prog_user` program to establish bidirectional forwarding of traffic. 

 

enter the left interface and then `ping` the right interface

```sh
$ t enter -n left
# ping fc00:dead:cafe:2::2
```

Check if the packets are forwarded 

```sh
$ sudo ./xdp_stats -d right

Collecting stats from BPF map
 - BPF map (bpf_map_type:6) id:183 name:xdp_stats_map key_size:4 value_size:16 max_entries:5
XDP-action
XDP_ABORTED            0 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:0.250185
XDP_DROP               0 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:0.250239
XDP_PASS               0 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:0.250234
XDP_TX                 0 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:0.250231
XDP_REDIRECT        1303 pkts (         0 pps)         153 Kbytes (     0 Mbits/s) period:0.250228

^C
```





#### TTL and HOP Limit 

TTL (Time-to-Live) and hop limit are both mechanisms used in networking to prevent packets from circulating indefinitely in a network and to manage the lifetime of packets. They are primarily used to ensure that packets are not stuck in loops or congested networks, and they provide a way to limit the time a packet spends in a network.

1. **TTL (Time-to-Live)**: TTL is a field in the IP header of IPv4 packets. It represents the number of hops (routers or gateways) that a packet is allowed to make before it is discarded. Each time a packet passes through a router, its TTL value is decremented by one. If the TTL reaches zero, the packet is discarded. The primary purpose of TTL is to prevent packets from endlessly circulating in the network, which could lead to congestion and waste of network resources.
2. **Hop Limit**: Hop limit is the equivalent concept for IPv6 packets. It is also known as "Time-to-Live" in IPv6, even though the name is slightly misleading. Like TTL in IPv4, the hop limit field in the IPv6 header represents the number of hops a packet is allowed to make. It is decremented by one at each router or gateway the packet passes through. If the hop limit reaches zero, the packet is dropped.



#### Two BPF maps

* **`tx_port` Map:** associates network device IDs with integer values. It's likely used to manage or track specific properties or configurations related to different network devices. The integer values associated with the network device IDs could represent various attributes, such as transmission ports or settings.

* **`redirect_params` Map:** stores Ethernet MAC addresses as keys and their corresponding MAC addresses as values. This is likely used for defining redirection rules for network traffic. When the source MAC address matches a key in this map, the corresponding value (destination MAC address) is used to redirect the traffic.



### Assign 4: 





#### bpf_fib_lookup

`bpf_fib_lookup` is a helper function provided by the Linux kernel that allows an eBPF program to perform a FIB lookup. This function takes an input packet and returns the result of the FIB lookup, which typically includes information about the next-hop or outgoing interface for the packet.







#### IP forwarding

IP forwarding, also known as packet forwarding, is a networking feature that allows a device, typically a router or a computer, to route network packets from one network segment to another. In simpler terms, it enables the device to act as an intermediary that directs data traffic between different networks.



#### HowTo

Create three test environments

```sh
$ t setup -n uno --legacy-ip
$ t setup -n dos --legacy-ip
$ t setup -n dres --legacy-ip
```

and then enable the IP forwarding

```sh
$ sudo sysctl net.ipv4.conf.all.forwarding=1
$ sudo sysctl net.ipv6.conf.all.forwarding=1
```

attach the `xdp_pass_func` function to the three inner virtual interfaces 

```sh
$ t enter -n uno
# ./xdp_loader --dev veth0 --progname xdp_pass_func
```

```sh
$ t enter -n dos
# ./xdp_loader --dev veth0 --progname xdp_pass_func
```

```sh
$ t enter -n dres
# ./xdp_loader --dev veth0 --progname xdp_pass_func
```

Load the XDP functions `xdp_router_func` into the three interfaces so that the network interfaces perform a redirection when network packet come to the interfaces. 

```sh
$ sudo ./xdp_loader --dev uno --progname xdp_router_func
$ sudo ./xdp_loader --dev dos --progname xdp_router_func
$ sudo ./xdp_loader --dev tres --progname xdp_router_func
```

Then we can ping under the 6 interfaces. For example we can enter:

```sh
$ t enter -n tres
```

and then ping the `dos` interface by

```sh
# ping fc00:dead:cafe:2::1
PING fc00:dead:cafe:2::1(fc00:dead:cafe:2::1) 56 data bytes
64 bytes from fc00:dead:cafe:2::1: icmp_seq=1 ttl=64 time=0.055 ms
64 bytes from fc00:dead:cafe:2::1: icmp_seq=2 ttl=64 time=0.112 ms
64 bytes from fc00:dead:cafe:2::1: icmp_seq=3 ttl=64 time=0.099 ms
64 bytes from fc00:dead:cafe:2::1: icmp_seq=4 ttl=64 time=0.109 ms
64 bytes from fc00:dead:cafe:2::1: icmp_seq=5 ttl=64 time=0.082 ms
64 bytes from fc00:dead:cafe:2::1: icmp_seq=6 ttl=64 time=0.140 ms
64 bytes from fc00:dead:cafe:2::1: icmp_seq=7 ttl=64 time=0.094 ms
64 bytes from fc00:dead:cafe:2::1: icmp_seq=8 ttl=64 time=0.140 ms
64 bytes from fc00:dead:cafe:2::1: icmp_seq=9 ttl=64 time=0.077 ms
64 bytes from fc00:dead:cafe:2::1: icmp_seq=10 ttl=64 time=0.144 ms
64 bytes from fc00:dead:cafe:2::1: icmp_seq=11 ttl=64 time=0.079 ms
64 bytes from fc00:dead:cafe:2::1: icmp_seq=12 ttl=64 time=0.140 ms
^C
--- fc00:dead:cafe:2::1 ping statistics ---
12 packets transmitted, 12 received, 0% packet loss, time 11261ms
rtt min/avg/max/mdev = 0.055/0.105/0.144/0.028 ms
# ping fc00:dead:cafe:2::2
PING fc00:dead:cafe:2::2(fc00:dead:cafe:2::2) 56 data bytes
64 bytes from fc00:dead:cafe:2::2: icmp_seq=1 ttl=63 time=0.067 ms
64 bytes from fc00:dead:cafe:2::2: icmp_seq=2 ttl=63 time=0.103 ms
64 bytes from fc00:dead:cafe:2::2: icmp_seq=3 ttl=63 time=0.092 ms
64 bytes from fc00:dead:cafe:2::2: icmp_seq=4 ttl=63 time=0.102 ms
64 bytes from fc00:dead:cafe:2::2: icmp_seq=5 ttl=63 time=0.102 ms
^C
```



We can check the Redirecting by checking the BPF map

``` sh
(base) clemens@ThinkPad-P15s:~/KUKA/xdp-tutorial-learning-notes/packet03-redirecting$ sudo ./xdp_stats -d dos
[sudo] password for clemens: 

Collecting stats from BPF map
 - BPF map (bpf_map_type:6) id:23 name:xdp_stats_map key_size:4 value_size:16 max_entries:5
XDP-action  
XDP_ABORTED            0 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:0.250156
XDP_DROP               0 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:0.250130
XDP_PASS               2 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:0.250131
XDP_TX                 0 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:0.250132
XDP_REDIRECT           8 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:0.250132

^C
```





## Tutorial 8 Monitor XDP tracepoint

* This tutorial mainly shows how a user space program `trace_load_and_stats.c`can access the tracing data of a XDP tracing instance (`SEC("tracepoint/xdp/xdp_exception")`) and tracks the number of the `xdp:xdp_exception` as the program `trace_load_and_stats.c` runs.

* The trace point can also be traced by the `trace-cmd`
  ```sh
  $ sudo trace-cmd record -e "xdp:xdp_exception"
  Hit Ctrl^C to stop recording
  ^CCPU0 data recorded at offset=0xad1000
      0 bytes in size
  CPU1 data recorded at offset=0xad1000
      0 bytes in size
  CPU2 data recorded at offset=0xad1000
      4096 bytes in size
  CPU3 data recorded at offset=0xad2000
      0 bytes in size
  CPU4 data recorded at offset=0xad2000
      4096 bytes in size
  CPU5 data recorded at offset=0xad3000
      0 bytes in size
  CPU6 data recorded at offset=0xad3000
      0 bytes in size
  CPU7 data recorded at offset=0xad3000
      0 bytes in size
  $ sudo trace-cmd report -l
  trace-cmd: No such file or directory
    Error: expected type 4 but read 5
  CPU 0 is empty
  CPU 1 is empty
  CPU 3 is empty
  CPU 5 is empty
  CPU 6 is empty
  CPU 7 is empty
  cpus=8
      ping-10053   2..s1  5602.514199: xdp_exception:        prog_id=158 action=ABORTED ifindex=11
      ping-10053   2..s1  5603.531297: xdp_exception:        prog_id=158 action=ABORTED ifindex=11
      ping-10053   2..s1  5604.555236: xdp_exception:        prog_id=158 action=ABORTED ifindex=11
      ping-10053   2..s1  5605.579193: xdp_exception:        prog_id=158 action=ABORTED ifindex=11
      ping-10053   2..s1  5606.603211: xdp_exception:        prog_id=158 action=ABORTED ifindex=11
      ping-10053   2..s1  5607.627185: xdp_exception:        prog_id=158 action=ABORTED ifindex=11
      ping-10053   2..s1  5608.651087: xdp_exception:        prog_id=158 action=ABORTED ifindex=11
      ping-10053   2..s1  5609.675123: xdp_exception:        prog_id=158 action=ABORTED ifindex=11
      ping-10053   2..s1  5610.699099: xdp_exception:        prog_id=158 action=ABORTED ifindex=11
      ping-10053   2..s1  5611.727110: xdp_exception:        prog_id=158 action=ABORTED ifindex=11
      ping-10053   2..s1  5612.747035: xdp_exception:        prog_id=158 action=ABORTED ifindex=11
      ping-10053   2..s1  5613.771018: xdp_exception:        prog_id=158 action=ABORTED ifindex=11
      ping-10053   2..s1  5614.794978: xdp_exception:        prog_id=158 action=ABORTED ifindex=11
      ping-10053   4..s1  5615.818884: xdp_exception:        prog_id=158 action=ABORTED ifindex=11
  ```

  



The eBPF programs can be attached also to tracepoints. 

There are several tracepoints related to the xdp tracepoint subsystem:

```sh
$ sudo ls /sys/kernel/debug/tracing/events/xdp/
mem_disconnect     
xdp_cpumap_enqueue  
xdp_exception     
xdp_redirect_map
mem_return_failed  
xdp_cpumap_kthread  
xdp_redirect      
xdp_redirect_map_err
mem_connect  
xdp_bulk_tx        
xdp_devmap_xmit     
xdp_redirect_err 
```

### Tracepoint program section

The bpf library expects the tracepoint eBPF program to be stored in a section with following name:

```sh
tracepoint/<sys>/<tracepoint>
```

where `<sys>` is the tracepoint subsystem and `<tracepoint>` is the tracepoint name, which can be done with following construct:

```sh
SEC("tracepoint/xdp/xdp_exception")
int trace_xdp_exception(struct xdp_exception_ctx *ctx)
```

### Tracepoint arguments

There’s single program pointer argument which points to the structure, that defines the tracepoint fields. Like for `xdp:xdp_exception` tracepoint:

```c
struct xdp_exception_ctx {
        __u64 __pad;      // First 8 bytes are not accessible by bpf code
        __s32 prog_id;    //      offset:8;  size:4; signed:1;
        __u32 act;        //      offset:12; size:4; signed:0;
        __s32 ifindex;    //      offset:16; size:4; signed:1;
};

int trace_xdp_exception(struct xdp_exception_ctx *ctx)
```

This struct is exported in tracepoint format file:

```sh
# cat /sys/kernel/debug/tracing/events/xdp/xdp_exception/format
...
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int prog_id;      offset:8;       size:4; signed:1;
        field:u32 act;  offset:12;      size:4; signed:0;
        field:int ifindex;      offset:16;      size:4; signed:1;
...
```



### Tracepoint attaching

To load a tracepoint program for this example we use following bpf library helper functions:

```c
struct bpf_object *obj;
int err;
struct bpf_link *link;

obj = bpf_object__open_file(cfg->filename, NULL);
...
err = bpf_object__load(obj);
...
link = bpf_program__attach_tracepoint(prog, "xdp", "xdp_exception");
```

To attach the program to the tracepoint we need to create a tracepoint perf event and attach the eBPF program to it, using its file descriptor. Under the hood this function sets up the `PERF_EVENT_IOC_SET_BPF` ioctl call:

```c
bpf_program__attach_tracepoint(prog, "xdp", "xdp_exception");
```



#### 





## AF_XDP

To run the example program, open two terminals. 

The first one

```sh
t ping
```

and in the other terminal

```sh
sudo ./af_xdp_user --dev enp0s31f6 --filename af_xdp_kern.o
```



### Small test for the XDP communication between two Linux machines.  

Send the data from KRC5 to the Linux Laptop which is loaded with a XDP socket. Here we choose the Linux Laptop to test the XDP communication because the KCR5 kernel was with the `CONFIG_BPF_STREAM_PARSER` flag disabled. 

connect the Linux machine with the KCR5 with a network cable. 

We could test the physical network connection with `ping` command



Start the user space application on the Linux machine. with

```sh
sudo ./af_xdp_user --dev enp0s31f6 --filename af_xdp_kern.o
```

and then 

on the KCR5 

```
echo "Hiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" | nc -u 172.20.255.15 5001
```

`5001` is the port number but is blocked by the linux machine somehow. But I did not spend time on checking this because the XDP is not affected because of this. 



On the terminal of Linux, we see the package is transfered by the XDP. 

```sh
received Data length: 160
--------------------------
�.��s`�vE���@@,-�������~EHiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
--------------------------
AF_XDP RX:            14 pkts (         0 pps)           1 Kbytes (     0 Mbits/s) period:2.000271
       TX:             0 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:2.000271
```









<mark>One point that we have been missing:</mark> 

XDP sockets are mainly for efficient packet processing and filtering at the kernel level and do not directly support sending packets back to the network from the XDP program itself: 

1. **XDP_DROP**: Drop the packet immediately.
2. **XDP_PASS**: Pass the packet to the next step in the networking stack.
3. **XDP_TX**: Transmit the packet directly from the receive path (loopback).
4. **XDP_REDIRECT**: Redirect the packet to another NIC or network device.
5. **XDP_ABORTED**: An error condition that indicates the XDP program could not execute properly.

Also from the return value we could find out that the XDP does not support sending from the userspace directly using the BPF map to the outsider network instances. 



### Ping between KRC5 and Ubuntu Linux

ping from the KRC5 

 ```sh
 ping 172.20.255.15
 ```

and then in the command line
``` sh
(base) clemens@ThinkPad-P15s:~/KUKA/xdp-tutorial-learning-notes/advanced03-AF_XDP$ sudo ./af_xdp_user --dev enp0s31f6 --filename af_xdp_kern.o
```

