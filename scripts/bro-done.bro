module Phish; 


export {	
	global STATS_TIME: interval  =  10 mins ; 
} 

event bro_done()
{
	#for (l in mail_links)
	#	print fmt("%s", mail_links[l]); 
}	

event bro_done()
{
	print fmt("########### from_name #################"); 
        for (from_name in smtp_from_name)
               print fmt ("%s -> %s", from_name, smtp_from_name[from_name]);

	print fmt("########### from_email #################"); 
        for (from_email in smtp_from_email)
               print fmt ("%s -> %s", from_email, smtp_from_email[from_email]);

	print fmt("########### smtp_from #################"); 
        for (from in smtp_from)
               print fmt ("%s -> %s", from, smtp_from[from]);

	for (to_name in email_recv_to_name)
		print fmt("TO_NAME: %s, %s", to_name, email_recv_to_name[to_name]); 
	
	for (to_email in email_recv_to_address)
		print fmt("TO_EMAIL: %s, %s", to_email, email_recv_to_address[to_email]); 

}

event log_stats()
{
        print fmt("STATS: mail_links: %s", |mail_links|); 
        log_reporter(fmt("STATS: mail_links: %s, smtp_from: %s, smtp_from_name: %s, smtp_from_email: %s, http_fqdn: %s, email_recv_to_name: %s, email_recv_to_address: %s", |Phish::mail_links|, |Phish::smtp_from|, |Phish::smtp_from_name|, |Phish::smtp_from_email|, |Phish::http_fqdn|, |Phish::email_recv_to_name|, |Phish::email_recv_to_address|),0);
        schedule STATS_TIME { Phish::log_stats() };
}

event bro_init()
{
        schedule STATS_TIME { Phish::log_stats() };
}
