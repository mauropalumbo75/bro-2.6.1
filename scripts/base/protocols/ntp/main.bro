module NTP;

# TODO: The recommended method to do dynamic protocol detection
# (DPD) is with the signatures in dpd.sig. 
# For the time being, we use port detection. 
const ports = { 123/udp };
redef likely_server_ports += { ports };

export {
        redef enum Log::ID += { LOG };

        type Info: record {
                ## Timestamp for when the event happened.
                ts:     	time    &log;
                ## Unique ID for the connection.
                uid:    	string  &log;
                ## The connection's 4-tuple of endpoint addresses/ports.
                id:     	conn_id &log;
		## The NTP version number (1, 2, 3, 4)
        	version:	count &log;
        	## The NTP mode being used
                mode:		count &log;
        	## The stratum (primary server, secondary server, etc.)
        	stratum:	count &log;
        	## The maximum interval between successive messages
        	poll:		interval &log;
        	## The precision of the system clock
        	precision:	interval &log;
        	## Total round-trip delay to the reference clock
        	root_delay:	interval &log;
        	## Total dispersion to the reference clock
        	root_disp:	interval &log;
        	## For stratum 0, 4 character string used for debugging
        	kiss_code:	string &optional &log;
        	## For stratum 1, ID assigned to the reference clock by IANA
        	ref_id:         string &optional &log;
        	## Above stratum 1, when using IPv4, the IP address of the reference clock
        	ref_addr:	addr &optional &log;
        	## Above stratum 1, when using IPv6, the first four bytes of the MD5 hash of the
        	## IPv6 address of the reference clock
        	ref_v6_hash_prefix: string &optional &log;
        	## Time when the system clock was last set or correct
        	ref_time:	time &log;
        	## Time at the client when the request departed for the NTP server
        	org_time:	time &log;
        	## Time at the server when the request arrived from the NTP client
        	rec_time:	time &log;
        	## Time at the server when the response departed for the NTP client
        	xmt_time:	time &log;
	};

        ## Event that can be handled to access the NTP record as it is sent on
        ## to the logging framework.
        global log_ntp: event(rec: Info);
}

redef record connection += {
        ntp: Info &optional;
};

event ntp_message(c: connection, is_orig: bool, msg: NTP::Message) &priority=5
{
	local info: Info;
	  info$ts  = network_time();
	  info$uid = c$uid;
	  info$id  = c$id;
	  info$version = msg$version;
          info$mode = msg$mode;
	  if ( msg$mode < 6 ) { 
 		info$stratum = msg$std_msg$stratum;
		info$poll =  msg$std_msg$poll;
		info$precision =  msg$std_msg$precision;
		info$root_delay =  msg$std_msg$root_delay;
		info$root_disp =  msg$std_msg$root_disp;

		if ( msg$std_msg?$kiss_code) 
			info$kiss_code =  msg$std_msg$kiss_code;
                if ( msg$std_msg?$ref_id)
                        info$ref_id =  msg$std_msg$ref_id;
                if ( msg$std_msg?$ref_addr)
                        info$ref_addr =  msg$std_msg$ref_addr;
                if ( msg$std_msg?$ref_v6_hash_prefix)
                        info$ref_v6_hash_prefix =  msg$std_msg$ref_v6_hash_prefix;

                info$ref_time =  msg$std_msg$ref_time;
                info$org_time =  msg$std_msg$org_time;
                info$rec_time =  msg$std_msg$rec_time;
                info$xmt_time =  msg$std_msg$xmt_time;

	  }

        # Copy the present packet info into the connection record
	# If more ntp packets are sent on the same connection, the newest one
	# will overwrite the previous
	c$ntp = info;

	# Add the service to the Conn::LOG
	add c$service["ntp"];
}

event ntp_message(c: connection, is_orig: bool, msg: NTP::Message) &priority=-5
{
        # Log every ntp packet into ntp.log
        Log::write(NTP::LOG, c$ntp);
}

event bro_init() &priority=5
{
    Analyzer::register_for_ports(Analyzer::ANALYZER_NTP, ports);

    Log::create_stream(NTP::LOG, [$columns = Info, $ev = log_ntp]);
}

