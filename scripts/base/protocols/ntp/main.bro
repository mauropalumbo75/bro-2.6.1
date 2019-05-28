module NTP;

# TODO: The recommended method to do dynamic protocol detection
# (DPD) is with the signatures in dpd.sig. 
# For the time being, we use port detection. 
const ports = { 123/udp };
redef likely_server_ports += { ports };

event bro_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_NTP, ports);
	}

