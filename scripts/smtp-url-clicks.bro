module Phish;

export {

        redef enum Notice::Type += {
		URLClick, 
		RareURLClick, 
		HistoricallyNewAttacker, 
		AddressSpoofer, 
		NameSpoofer, 
		HTTPSensitivePOST, 
	}; 
		
		type mi : record { 
			uid: string &default="" ; 
			from: string &default="" ; 
			to: string &default="" ;
			subject: string &default="" ;
		} ; 
        
		global mail_links_expire_func: function(t: table[string] of mi, link: string): interval ; 
		global mail_links: table [string] of mi &create_expire=EXPIRE_INTERVAL  &expire_func=mail_links_expire_func ; 
	        global mail_links_bloom: opaque of bloomfilter ;
		global referrer_link_already_seen: set[string] ; 
		global check_smtpurl_in_http: function(rec: HTTP::Info); 
		
		global m_w_smtpurls_add: event (link: string, mail_info: mi); 
		global w_m_smtpurls_new: event (link: string, mail_info: mi); 
		global w_m_smtp_url_click: event (link: string, mail_info: mi, c: connection ); 
		#global w_m_smtp_url_click: event (link: string, mail_info: mi, rec: HTTP::Info); 
		global populate_mail_links: function(link: string, mail_info: mi); 
		
		global track_post_requests: table[addr] of string &synchronized &create_expire= 2 days &redef ;
}


function mail_links_expire_func(t: table[string] of mi, link: string): interval 
{

	local domain = get_domain_from_url(link); 
		
	local seen = bloomfilter_lookup(uninterestig_fqdns, domain); 

	if (seen >0)
	{ 
		#log_reporter(fmt("URL is uninteresting so deleting from mail_links: %s", link),0); 
		bloomfilter_add(mail_links_bloom, link); 
		return 0 secs; 
	} 
	
	return EXPIRE_INTERVAL ; 

} 
event bro_init()
{
        mail_links_bloom = bloomfilter_basic_init(0.0001, 400000);
}


@if ( Cluster::is_enabled() )
@load base/frameworks/cluster
redef Cluster::manager2worker_events += /Phish::m_w_smtpurls_add/;
redef Cluster::worker2manager_events += /Phish::w_m_smtpurls_new|Phish::w_m_smtp_url_click/;
@endif


function is_url_in_email(link: string): bool 
{
	local seen : count = 0 ;  
	
	if (link in mail_links)
	{ 
		seen = 1; 
		return T; 
	}
		
	seen = bloomfilter_lookup(mail_links_bloom, link); 

	if (seen > 0)
		return T; 

	return F ; 
} 
	
	
event  Phish::process_smtp_urls(c:connection, url:string)
{

	if (! c?$smtp) 
		return ;

	local to_list="" ; 

	if (c?$smtp && c$smtp?$to) {
		for (to in c$smtp$to) { to_list += fmt ("%s", to); }
	} 

	local mail_info: mi ; 

	mail_info$uid= c$smtp?$uid ? fmt("%s", c$smtp$uid) : "" ; 
	mail_info$from=c$smtp?$from ? fmt("%s", c$smtp$from) : "" ; 
	mail_info$to=fmt("%s", to_list); 
	mail_info$subject=c$smtp?$subject ? fmt("%s", c$smtp$subject) : "" ; 

	local link  = url ; 

	if (link !in mail_links ) #&& ignore_file_types !in link && ignore_fp_links !in link ) { 
	{ 
		populate_mail_links(link, mail_info); 
	} 	
}


@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
event Phish::m_w_smtpurls_add (link: string, mail_info: mi)
{
	if (link !in mail_links ) {
		#log_reporter(fmt("m_w_smtpurls_add: link: %s, mail_info: %s", link, mail_info),5); 
               	mail_links[link] = mail_info ;
	} 
}
@endif 


@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )

event Phish::w_m_smtpurls_new(link: string, mail_info: mi)
{
	#log_reporter(fmt("w_m_smtpurls_new: link: %s, mail_info: %s", link, mail_info),5); 
 	event Phish::m_w_smtpurls_add (link, mail_info); 
}

@endif 

@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| ! Cluster::is_enabled() )
#event Phish::w_m_smtp_url_click(link: string, mail_info: mi, rec: HTTP::Info)
event Phish::w_m_smtp_url_click(link: string, mail_info: mi, c: connection) 
{
	#log_reporter(fmt("clicked_URL : link: %s, mail_info: %s, smtp_from: %s", link, mail_info, smtp_from[mail_info$from]),0);
	local _msg = "" ; 

	local domain = get_domain_from_url(link); 

	local from_name = get_email_name(mail_info$from) ; 
	local from_address = get_email_address(mail_info$from) ; 
	local full_from=mail_info$from ; 
	
	### to update the number of clicks seen by a perticular 
	### from_name and a from_address
	
	smtp_from[full_from]$num_clicks+= 1; 
	if (from_name != "") smtp_from_name[from_name]$num_clicks+=1;
	smtp_from_email[from_address]$num_clicks +=1 ; 

	if (isRareURLClick(domain) )
	{
		_msg = fmt("Rare clicked_URL: link: %s, mail_info: %s, http_fqdn: %s", link, mail_info, http_fqdn[domain]); 
		log_reporter(fmt ("%s",_msg),0);
		NOTICE([$note=Phish::RareURLClick, $msg=_msg, $conn=c]);

		if (isHistoricallyNewAttacker(domain, from_name, from_address) )
		{ 
			NOTICE([$note=Phish::HistoricallyNewAttacker, $msg=_msg, $conn=c]);
		} 

		if (isNameSpoofer(domain, from_name, full_from) ) 
		{ 
			NOTICE([$note=Phish::NameSpoofer, $msg=_msg, $conn=c]);
	
		} 
		
		if (isAddressSpoofer(domain, from_address, full_from) )
		{ 
			NOTICE([$note=Phish::AddressSpoofer, $msg=_msg, $conn=c]);
		} 
			
	} 
	else 
	{
		local seen = bloomfilter_lookup(uninterestig_fqdns, domain);

	        if (seen > 0)
		{ 
			
			NOTICE([$note=Phish::URLClick, $msg=fmt("URL %s [%s]", link, mail_info), $conn=c]);
		} 
	} 

} 
@endif 

function populate_mail_links(link: string, mail_info: mi )
{

	if (link !in mail_links ) 
	{ 
               	mail_links[link] = mail_info ;
		bloomfilter_add(mail_links_bloom, link); 

		#log_reporter(fmt("populate_mail_links: link: %s, mail_info: %s", link, mail_info),5); 
	@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
		event Phish::w_m_smtpurls_new(link, mail_info); 
	@endif

	} 
} 

#event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority=-3
event HTTP::log_http(rec: HTTP::Info) &priority=-6
{
	check_smtpurl_in_http(rec) ; 
} 

function check_smtpurl_in_http( rec: HTTP::Info)
{ 
	
	if ( ! connection_exists(rec$id) )
                return;

	local c = lookup_connection(rec$id); 

        #local rec = c$http ;
	#local dst = c$id$resp_h ; 
	#local src = c$id$orig_h ; 
	#local str = HTTP::build_url_http(c$http); 

	local src = rec$id$orig_h ; 
	local dst = rec$id$resp_h ; 
	local str = HTTP::build_url_http(rec); 

	local seen = bloomfilter_lookup(mail_links_bloom, str); 

	### debugging http_message_done runs twice 
	###log_reporter(fmt("log_http RAN for :%s, %s", str, c),0); 

	if ((seen >0 || str in mail_links) && dst !in track_post_requests)
	{
       		track_post_requests[dst] = fmt ("%s clicked %s to %s", src, str, dst);
		#print fmt ("POST request track: %s", track_post_requests[dst]);
	}

	if (seen >0)  
	{
		NOTICE([$note=Phish::URLClick, $msg=fmt("URL %s", str), $conn=c]);
	} 
	else if ((str in Phish::mail_links && ignore_file_types !in str && ignore_site_links !in str && str !in link_already_seen) ) 
	{ 		
		#NOTICE([$note=Phish::URLClick, $msg=fmt("URL %s [%s]", str, Phish::mail_links[str]), $conn=c]);
		add Phish::link_already_seen[str] ; 

		@if (( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER ) || ! Cluster::is_enabled() ) 
			#event Phish::w_m_smtp_url_click(str, Phish::mail_links[str], rec); 
			event Phish::w_m_smtp_url_click(str, mail_links[str], c); 
		@endif 

	} 	

	if (c$http?$referrer && c$http$referrer in mail_links) 
	{ 
		if (str !in Phish::mail_links)
		{ 
			Phish::mail_links[str] = Phish::mail_links[c$http$referrer] ; 
		} 

	} 

	### need to figure out a way to track referrers 
	### need to figure out a way to check for md5 and binary downloads 
} 



#event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority = -4
#        {
#        # The reply body is done so we're ready to log.
#        if ( ! is_orig )
#                {
#                # If the response was an informational 1xx, we're still expecting
#                # the real response later, so we'll continue using the same record.
#                if ( ! (c$http?$status_code && code_in_range(c$http$status_code, 100, 199)) )
#                        {
#				
#                        }
#                }
#        }
#
#event connection_state_remove(c: connection) &priority=-4
#        {
#        # Flush all pending but incomplete request/response pairs.
#        if ( c?$http_state )
#                {
#                for ( r in c$http_state$pending )
#                        {
#                        # We don't use pending elements at index 0.
#                        if ( r == 0 ) next;
#				
#                        }
#                }
#        }
