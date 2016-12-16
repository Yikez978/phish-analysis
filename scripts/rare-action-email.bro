module Phish; 

export {

@ifndef (SECS_ONE_DAY) 
	const SECS_ONE_DAY=10 usecs;
@endif 

	const NUM_DAYS_TO_WATCH = 10 ; 

	global add_to_from_email: function(rec: SMTP::Info); 
	global add_to_from_name: function(rec: SMTP::Info); 
	global add_to_from: function(rec: SMTP::Info) ; 
	
	#global Phish::w_m_smtp_rec_new: event (sr: smtp_rec) ; 
	global Phish::w_m_smtp_rec_new: event (rec: SMTP::Info) ; 
	global Phish::m_w_smtpurls_stop : event (sr: SMTP::Info) ; 

	global get_email_address: function(sender: string): string; 
	global get_email_name: function(sender: string): string; 
	global update_recv_stats: function (rec: SMTP::Info); 

}

function get_email_address(sender: string): string
{

	local pat = />|<| |\"|\'/;
        local to_n = split_string(sender,/</) ;

        local to_name: string;

        if (|to_n| == 1)
        {
                to_name =  strip(gsub(to_n[0], pat, ""));
        }
        else
        {
                to_name =  strip(gsub(to_n[1], pat, ""));
        }

        to_name=to_lower(to_name);

        return to_name ;
}

function get_email_name(sender: string): string
{
	if (/</ !in sender)
		return "" ;
	
	local pat = /\"|\'/;
	
	local s=strip(gsub(sender, pat, "")); 

	return strip(split_string(s,/</)[0]); 
}


@if ( Cluster::is_enabled() )
@load base/frameworks/cluster
redef Cluster::manager2worker_events += /Phish::m_w_smtp_rec_stop/;
redef Cluster::worker2manager_events += /Phish::w_m_smtp_rec_new/;
@endif


@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
event Phish::m_w_smtp_rec_stop (sr: SMTP::Info) 
{
	#log_reporter(fmt("m_w_smtpurls_stop: %s", rs),5);
	return ; 
}
@endif


@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) || ! Cluster::is_enabled()) 

#event Phish::w_m_smtp_rec_new(sr: smtp_rec) 
event Phish::w_m_smtp_rec_new(sr: SMTP::Info) 
{
        #log_reporter(fmt("w_m_smtp_rec_new: %s", sr),5);
	
	update_recv_stats(sr); 
	add_to_from(sr); 
	add_to_from_name(sr); 
	add_to_from_email(sr); 

}
@endif

function update_recv_stats(rec: SMTP::Info)
{
	# mailfrom        rcptto  date    from    to      cc      reply_to

	local to_name: string = "" ; 
	local to_email: string = "" ; 

	#print fmt ("REEEEEEEEEEEEEEEEEEEEEEEEEREC is: %s", rec); 

	#if (rec?$rcptto)
	#{ 	
	#	for (to in rec$rcptto)
	#	{ 
	#		to_email = get_email_address(to); 	
	#		print fmt ("to_email: %s", to_email); 
        # 	
	#		if (to_email !in email_recv_to_address)
        #   		{
        #                        local a: recv_to_address ;
        #                        email_recv_to_address[to_email]=a ;
        #                }
	#		email_recv_to_address[to_email]$emails_recv += 1; 
	#	} 
	#} 

	if (rec?$to)
	{ 
		for (to in rec$to)
		{ 
			#print fmt("TOOOOOO: to: %s", to); 
			to_name = get_email_name(to); 
			to_email = get_email_address(to); 	
	
			if (to_name != "")
			{  
				if (to_name !in email_recv_to_name)
				{ 
					local b: recv_to_name; 
					b$emails_recv=0; 
					email_recv_to_name[to_name]=b ; 
				} 
				email_recv_to_name[to_name]$emails_recv += 1; 
			 } 

			if (to_email !in email_recv_to_address) 
			{ 
				local c: recv_to_address ;
				c$emails_recv = 0 ; 
				email_recv_to_address[to_email]=c ; 
			} 

			email_recv_to_address[to_email]$emails_recv += 1; 
		} 
	} 

	if (rec?$cc)
	{ 
		for (cc in rec$cc)
		{ 
			#print fmt("TOOOOOO: cc: %s", cc); 
			to_name = get_email_name(cc); 
			to_email = get_email_address(cc); 	
			
			if (to_name != "")
                        {
                                if (to_name !in email_recv_to_name)
                                {
                                        local d: recv_to_name;
					d$emails_recv = 0 ; 
                                        email_recv_to_name[to_name]=d ;
                                }

                                email_recv_to_name[to_name]$emails_recv += 1;
                         }

                        if (to_email !in email_recv_to_address)
                        {
                                local e: recv_to_address ;
				e$emails_recv = 0 ; 
                                email_recv_to_address[to_email]=e ;
                        }

                        email_recv_to_address[to_email]$emails_recv += 1;
	
		}
	} 
	
} 


function add_to_from(rec: SMTP::Info) 
{ 
	local from_name = rec?$from ? strip(split_string(rec$from,/</)[0]) : "" ;
	local from_email = rec?$from ? get_email_address(rec$from) : ""  ; 
	local from = rec?$from ? rec$from : "" ; 

	if (from == "" ) 
	{ 	
		return ; 
	} 


	if (from !in smtp_from)
        {
                local c:from_rec;
                c$days_sent = vector();

                smtp_from[from]=c;
        }

        smtp_from[from]$emails_sent += 1 ;
        add smtp_from[from]$email[from_email];

        local n = |smtp_from[from]$days_sent| ;

        if (n < NUM_DAYS_TO_WATCH)
        {
                if (n == 0 )
                        smtp_from[from]$days_sent[|smtp_from[from]$days_sent|] = rec$ts ;
                else if ( network_time() - smtp_from[from]$days_sent[n-1] > SECS_ONE_DAY)
                        smtp_from[from]$days_sent[|smtp_from[from]$days_sent|] = rec$ts ;
        }

} 

function add_to_from_name(rec: SMTP::Info)
{ 

	local from_name = rec?$from ? strip(split_string(rec$from,/</)[0]) : "" ;
	local from_email = rec?$from ? get_email_address(rec$from) : ""  ; 
	local from = rec?$from ? rec$from : "" ; 

	if (from == "" ) 
	{ 	
		return ; 
	} 

	#### how many email addresses a given from name has 
	### how many messages a given from_name has sent 
	### how often

	if (from_name !in smtp_from_name)
	{
		local b:from_name_rec; 
		b$days_sent = vector(); 

		smtp_from_name[from_name]=b; 

	} 

	smtp_from_name[from_name]$emails_sent += 1 ; 
	add smtp_from_name[from_name]$email[from_email]; 

	if(from_name in email_recv_to_name)
		smtp_from_name[from_name]$emails_recv = email_recv_to_name[from_name]$emails_recv ; 

	local n = |smtp_from_name[from_name]$days_sent| ; 

	if (n < NUM_DAYS_TO_WATCH)
	{
		if (n == 0 )
			smtp_from_name[from_name]$days_sent[|smtp_from_name[from_name]$days_sent|] = rec$ts ; 
		else if ( network_time() - smtp_from_name[from_name]$days_sent[n-1] > SECS_ONE_DAY)
			smtp_from_name[from_name]$days_sent[|smtp_from_name[from_name]$days_sent|] = rec$ts ;
	} 
}


function add_to_from_email(rec: SMTP::Info)
{

	local from_name = rec?$from ? strip(split_string(rec$from,/</)[0]) : "" ;
	local from_email = rec?$from ? get_email_address(rec$from) : ""  ; 
	local from = rec?$from ? rec$from : "" ; 

	if (from == "" ) 
	{ 
		return ; 
	} 
		
	#### how many from names a given email address has 
	### how many messages a given email address has sent 
	### how often 

	if (from_email !in smtp_from_email)
	{
		local a:from_email_rec; 
		a$days_sent = vector(); 

		smtp_from_email[from_email]=a; 

	} 

	smtp_from_email[from_email]$emails_sent += 1 ; 
	add smtp_from_email[from_email]$name[from_name]; 

	if (from_email in email_recv_to_address) 
		smtp_from_email[from_email]$emails_recv = email_recv_to_address[from_email]$emails_recv ; 


	local n = |smtp_from_email[from_email]$days_sent| ; 

	if (n < NUM_DAYS_TO_WATCH)
	{
		if (n == 0 )
			smtp_from_email[from_email]$days_sent[|smtp_from_email[from_email]$days_sent|] = rec$ts ; 
		else if ( network_time() - smtp_from_email[from_email]$days_sent[n-1] > SECS_ONE_DAY)
			smtp_from_email[from_email]$days_sent[|smtp_from_email[from_email]$days_sent|] = rec$ts ;
	}
}

event SMTP::log_smtp(rec : SMTP::Info)
{

	#if (/250 ok/ !in rec$last_reply ) 
	#	return ; 

	if (! rec?$from)
		return ; 

	local sr: smtp_rec ; 
	
	sr$ts = rec$ts ; 
	sr$from = rec$from ; 

	event Phish::w_m_smtp_rec_new(rec); 
	
} 

#### [ts=1478544472.00721, uid=CSThuVID7RQUhU4td, id=[orig_h=128.3.63.21, orig_p=59130/tcp, resp_h=184.169.177.108, resp_p=80/tcp], trans_depth=1, method=GET, host=http.00.s.sophosxl.net, uri=/V3/01/181.50.89.52.ip/, referrer=<uninitialized>, version=1.1, user_agent=SXL/3.1, request_body_len=0, response_body_len=2, status_code=200, status_msg=OK, info_code=<uninitialized>, info_msg=<uninitialized>, tags={\x0a\x0a}, username=<uninitialized>, password=<uninitialized>, capture_password=F, proxied=<uninitialized>, range_request=F, orig_fuids=<uninitialized>, orig_filenames=<uninitialized>, orig_mime_types=<uninitialized>, resp_fuids=[FSW18c3ENGSVm4YNgk], resp_filenames=<uninitialized>, resp_mime_types=<uninitialized>, current_entity=<uninitialized>, orig_mime_depth=1, resp_mime_depth=1]

# SMTP record: [ts=1447239496.283309, uid=CdxXhu1NmUoJ6x5Ete, id=[orig_h=209.85.220.42, orig_p=33920/tcp, resp_h=128.3.41.120, resp_p=25/tcp], trans_depth=1, helo=mail-pa0-f42.google.com, mailfrom=aashish043@gmail.com, rcptto={\x0aasharma@lbl.gov\x0a}, date=Wed, 11 Nov 2015 02:58:14 -0800, from=Aashish Sharma <aashish043@gmail.com>, to={\x0aContacts <asharma@lbl.gov>\x0a}, cc=<uninitialized>, reply_to=<uninitialized>, msg_id=<CFEB0CB3-38FB-425F-9FFF-5DE3FE5EBE65@gmail.com>, in_reply_to=<uninitialized>, subject=dude click on this link , x_originating_ip=<uninitialized>, first_received=from [192.168.0.20] (c-50-173-240-3.hsd1.ca.comcast.net. [50.173.240.3])        by smtp.gmail.com with ESMTPSA id j5sm8870813pbq.74.2015.11.11.02.58.15        for <asharma@lbl.gov>        (version=TLSv1/SSLv3 cipher=OTHER);        Wed, 11 Nov 2015 02:58:15 -0800 (PST), second_received=by padhx2 with SMTP id hx2so28530313pad.1        for <asharma@lbl.gov>; Wed, 11 Nov 2015 02:58:16 -0800 (PST), last_reply=250 ok:  Message 4466494 accepted, path=[128.3.41.120, 209.85.220.42, 50.173.240.3], user_agent=Apple Mail (2.3094), tls=F, process_received_from=T, has_client_activity=T, entity=<uninitialized>, fuids=[FZfq0c1FW3RslSbJGd, Fyhta5NxJtGwP31Jj]]
