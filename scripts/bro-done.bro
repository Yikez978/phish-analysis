module Phish; 


export {	
	global STATS_TIME: interval  =  10 mins ; 

	 redef enum Notice::Type += {
		WRITER_POSTGRESQL_CRASH, 
	} ; 
		
} 

event log_stats()
{
        log_reporter(fmt("STATS: mail_links: %s, smtp_from: %s, smtp_from_name: %s, smtp_from_email: %s, http_fqdn: %s, email_recv_to_name: %s, email_recv_to_address: %s", |Phish::mail_links|, |Phish::smtp_from|, |Phish::smtp_from_name|, |Phish::smtp_from_email|, |Phish::http_fqdn|, |Phish::email_recv_to_name|, |Phish::email_recv_to_address|),0);
        schedule STATS_TIME { Phish::log_stats() };
}

event bro_init()
{
        schedule STATS_TIME { Phish::log_stats() };
}


event reporter_error(t: time , msg: string , location: string )
{
	print fmt ("EVENT: bro-done Reporter ERROR: %s, %s, %s", t, msg, location); 

	if (/WRITER_POSTGRESQL/ in msg)
	{
		NOTICE([$note=Phish::WRITER_POSTGRESQL_CRASH, $msg=msg]); 
	} 

} 
