# finalProject-HanksRevenge

## Team Roles
Evan: Protocol: DNS, written in Python  
Shawn: Implant beacon callback  
Audrey: Impement initial commands - 1) ps, 2) whoami, 3) hostname, 4) getpid, 5) ls  


## Implant C2 interaction
	C2(sends cmd number and input data) --> implant(Receives on socket, passes to command handler along with data buffer)
	-->(Command.c receives input buffer and len, given pointer (*Pbyte) data buffer and (*DWORD)) -> after command returns, the implant sends this to C2
