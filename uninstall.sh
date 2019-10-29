# TODO: 只删除我们创建的规则，保留原有的
# iptables -L | grep -P "trap-scan|scanner" 
iptables -F
iptables -F trap-scan
iptables -X trap-scan
ipset destroy scanner-ip-set
ipset destroy pub-port-set
