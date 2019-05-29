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
        };

        ## Event that can be handled to access the NTP record as it is sent on
        ## to the logging framework.
        global log_ntp: event(rec: Info);
}

event ntp_message(c: connection, msg: NTP::Message)
        {
        # Log info on ntp.log
        local info: Info;
        info$ts  = network_time();
        info$uid = c$uid;
        info$id  = c$id;
        info$mode = msg$mode;

        Log::write(NTP::LOG, info);
        }

event bro_init() &priority=5
{
    Log::create_stream(NTP::LOG, [$columns = Info, $ev = log_ntp]);
}

