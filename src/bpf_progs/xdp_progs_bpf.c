/*

Blacklist xdp eBPF program
This xdp map has different maps which contains information 
of blacklisted packets. 

What is a blacklisted? 
A packet is blacklisted if any of its content is not allowed
such as dest ip, src ip, mac address, type of protocol, ports etc...

The xdp program analyzes layer by layer by layer
link layer 
    At the link layer the xdp program can by 
        - SRC MAC 
        - TYPE OF PACKET - ARP, IPV4, IPV6
ip layer 
    At this layer the packets can be blocked by 
        - SRC IP 
        - DST IP 
        -   
network layer
application layer 

if only it passes through all layer then the packets is allowed
if it is blocked at any one layer then its fucked


*/


#include<linux/bpf.h>
#include<bpf/bpf_helpers.h>
#include<linux/if_ether.h>
#include<bpf/bpf_endian.h>

#define True 1
#define False 0
#define IP_BLOCKING 3


//Link Layer
// SRC MAC address 
struct {
    __uint(type, BPF_MAP_TYPE_HASH); 
    __uint(max_entries, 1024);
    __type(key, unsigned char[6]);
    __type(value, __u8);

}l_src_mac_map SEC(".maps"); 

//IP based blocking, block all packets if they are IPv4, IPv6 or ARP
struct { 
    __uint(type, BPF_MAP_TYPE_HASH); 
    __uint(max_entries, IP_BLOCKING);
    __type(key, __u8);
    __type(value, __u8); 
}l_ip_type_map SEC(".maps"); 

// given the eth header of the packet 
// checks the blacklist of src mac address and ip type
// if blacklisted returns 1 else returns 0
int link_layer_scan(struct ethhdr *eth){ 

    //get the src MAC 
    char src_mac[ETH_ALEN]; 
    bpf_probe_read_kernel(&src_mac, ETH_ALEN, (void *)eth->h_source); 
    __u8 value; 
    value = bpf_map_lookup_elem(&l_src_mac_map, &src_mac); 
    if (value){

        //this src mac address is blacklisted
        return False;
    }

    // check IP type
    int protocol = bpf_htons(eth->h_proto);
    value = bpf_map_lookup_elem(&l_ip_type_map, &protocol); 
    if (value){ 
        // this means a specific type of IP packet was blacklisted
        return False; 
    }

    return True;

}

SEC("XDP")
int beewall(struct xdp_md *ctx){ 

    int ret = False;

    void *data_start = (void *)(long) ctx->data; 
    void *data_end = (void *)(long)ctx->data_end;
    if (data_start + sizeof(struct ethhdr) > data_end){
        return 0;
    }
    struct ethhdr *eth = data_start; 
    ret = link_layer_scan(eth);
    if (!ret){ 
        return XDP_DROP; 
    }

    // ret = ip_layer_scan();
    // if (!ret){ 
    //     return XDP_DROP; 
    // }

    // ret = network_layer_scan(); 
    // if (!ret){ 
    //     return XDP_DROP;
    // }

    // ret = applciation_layer_scan(); 
    // if (!ret){ 
    //     return XDP_DROP;
    // }

    return XDP_PASS;
}