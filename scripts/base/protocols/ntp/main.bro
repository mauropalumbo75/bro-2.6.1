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
                ts:     time    &log;
                ## Unique ID for the connection.
                uid:    string  &log;
                ## The connection's 4-tuple of endpoint addresses/ports.
                id:     conn_id &log;
                ## The mode
                mode:   count &log;
		## For mode==6, add the OpCode
		OpCode:	count &log &optional;
                ## For mode==7, add the ReqCode
                ReqCode: count &log &optional;
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
  	if ( c?$ntp )
  	  info = c$ntp;
  	else
  	{
	  info$ts  = network_time();
	  info$uid = c$uid;
	  info$id  = c$id;
          info$mode = msg$mode;
	}

	
        if ( msg?$control_msg && msg$control_msg?$OpCode )
        {
               info$OpCode = msg$control_msg$OpCode;
        }
        if ( msg?$mode7_msg && msg$mode7_msg?$ReqCode )
        {
               info$ReqCode = msg$mode7_msg$ReqCode;
        }

	c$ntp = info;
	# Add the service to the Conn::LOG
	add c$service["ntp"];
}

event ntp_message(c: connection, is_orig: bool, msg: NTP::Message) &priority=-5
{
	# TODO: is it useful to log packets in both directions?
	#if ( ! is_orig )
  	#{
  	   Log::write(NTP::LOG, c$ntp);
	#}
}

event bro_init() &priority=5
{
    Analyzer::register_for_ports(Analyzer::ANALYZER_NTP, ports);

    Log::create_stream(NTP::LOG, [$columns = Info, $ev = log_ntp]);
}

