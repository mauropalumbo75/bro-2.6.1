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
        	## Key used to designate a secret MD5 key
        	key_id:		count &optional &log;
        	## MD5 hash computed over the key followed by the NTP packet header and extension fields
        	digest:		string &optional &log;
        	## Number of extension fields  (which are not currently parsed)
        	num_exts:	count &default=0 &log;

        	## An integer specifying the command function. Values currently defined includes:
        	## 1 read status command/response
        	## 2 read variables command/response
        	## 3 write variables command/response
        	## 4 read clock variables command/response
        	## 5 write clock variables command/response
        	## 6 set trap address/port command/response
        	## 7 trap response
        	## Other values are reserved.
        	OpCode          : count &log;
        	## The response bit. Set to zero for commands, one for responses.
        	resp_bit        : bool &log;
        	## The error bit. Set to zero for normal response, one for error response.
		err_bit         : bool &log;
        	## The more bit. Set to zero for last fragment, one for all others.
	        more_bit        : bool &log;
        	## The sequence number of the command or response
	        sequence        : count &log;
        	## The current status of the system, peer or clock
	        status          : count &log;    
        	## A 16-bit integer identifying a valid association
	        association_id  : count &log;

		## An implementation-specific code which specifies the
		## operation to be (which has been) performed and/or the
		## format and semantics of the data included in the packet.
        	ReqCode         : count &log;
        	## The authenticated bit. If set, this packet is authenticated.
        	auth_bit        : bool &log;
        	## For a multipacket response, contains the sequence
       		## number of this packet.  0 is the first in the sequence,
        	## 127 (or less) is the last.  The More Bit must be set in
        	## all packets but the last.
        	sequence        : count &log;
        	## The number of the implementation this request code
        	## is defined by.  An implementation number of zero is used
        	## for requst codes/data formats which all implementations
        	## agree on.  Implementation number 255 is reserved (for
        	## extensions, in case we run out).
        	implementation  : count &log;
        	##  Must be 0 for a request.  For a response, holds an error
        	##  code relating to the request.  If nonzero, the operation
        	##  requested wasn't performed.
        	##
        	##               0 - no error
        	##               1 - incompatible implementation number
        	##               2 - unimplemented request code
        	##               3 - format error (wrong data items, data size, packet size etc.)
        	##               4 - no data available (e.g. request for details on unknown peer)
        	##               5-6 I don't know
        	##               7 - authentication failure (i.e. permission denied)
        	err             : count &log;
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

		if ( info?$kiss_code) 
			info$kiss_code =  msg$std_msg$kiss_code;
                if ( info?$ref_id)
                        info$ref_id =  msg$std_msg$ref_id;
                if ( info?$ref_addr)
                        info$ref_addr =  msg$std_msg$ref_addr;
                if ( info?$ref_v6_hash_prefix)
                        info$ref_v6_hash_prefix =  msg$std_msg$ref_v6_hash_prefix;

                info$ref_time =  msg$std_msg$ref_time;
                info$org_time =  msg$std_msg$org_time;
                info$rec_time =  msg$std_msg$rec_time;
                info$xmt_time =  msg$std_msg$xmt_time;

                if ( info?$key_id)
                        info$key_id =  msg$std_msg$key_id;
                if ( info?$digest)
                        info$digest =  msg$std_msg$digest;

		info$num_exts =  msg$std_msg$num_exts;
	  }

          if ( msg$mode==6 ) {
             info$OpCode = msg$control_msg$OpCode;
             info$resp_bit = msg$control_msg$resp_bit;
             info$err_bit = msg$control_msg$err_bit;
             info$more_bit = msg$control_msg$more_bit;
             info$sequence = msg$control_msg$sequence;
             info$status = msg$control_msg$status;
             info$association_id = msg$control_msg$association_id;
	  }

          if ( msg$mode==7 ) {
             info$ReqCode = msg$mode7_msg$ReqCode;
	     info$auth_bit = msg$mode7_msg$auth_bit;
	     info$sequence = msg$mode7_msg$sequence;
	     info$implementation = msg$mode7_msg$implementation;
	     info$err = msg$mode7_msg$err;
	  }

        # Copy the present packet info into the connection record
	# If more ntp packets are sent on the same connection, the newest one
	# will overwrite the previous
	c$ntp = info;

	# Log every ntp packet into ntp.log
	Log::write(NTP::LOG, info);

	# Add the service to the Conn::LOG
	add c$service["ntp"];
}

event bro_init() &priority=5
{
    Analyzer::register_for_ports(Analyzer::ANALYZER_NTP, ports);

    Log::create_stream(NTP::LOG, [$columns = Info, $ev = log_ntp]);
}

