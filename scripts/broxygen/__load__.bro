@load test-all-policy.bro

# Scripts which are commented out in test-all-policy.bro.
@load protocols/ssl/notary.bro
@load frameworks/control/controllee.bro
@load frameworks/control/controller.bro
@load frameworks/files/extract-all-files.bro
@load policy/misc/dump-events.bro
@load policy/protocols/dhcp/deprecated_events.bro
@load policy/protocols/smb/__load__.bro

@load ./example.bro

event bro_init()
	{
	terminate();
	}
