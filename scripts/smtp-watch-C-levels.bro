module Phish; 

#@load smtp-encoded-subject.bro  
#redef SMTP::generate_md5 += /application\/*/;
#redef exit_only_after_terminate=T ; 

export { 
	
	redef enum Notice::Type += {
                # Indicates that an MD5 sum was calculated for an HTTP response body.
		Phish, 
		LabPhish, 
                Phish_MD5,
                Phish_Attachment,
                Phish_Indicator,
		Phish_Mailfrom,
		Phish_Mailto,
		Phish_from,
		ReplyToPhish,
		Phish_subject,
		Phish_rcptto,
		Phish_path,
		Phish_Decoded_Subject, 
	}; 

type smtp_phishIdx: record {
        indicator: string; 
};

# md5sum	comment 

type smtp_phishVal: record {
        indicator: string; 
        #comment: string &optional &default="null";
};

        global smtp_phish_indicators: table[string] of smtp_phishVal &synchronized &redef ; 
        #global smtp_phish_feed="/usr/local/bro-2.1/share/bro/site/feeds/smtp_phish_indicators.out" &redef ; 
        global smtp_phish_feed="/YURT/feeds/BRO-feeds/smtp_phish_indicators.out" &redef ; 


### feeds for flagging sender and subject which are part of log_smtp event

## Legit addresses 

type legitIdx: record {
        indicator: string;
};

# md5sum        comment

type legitVal: record {
        indicator: string;
        #comment: string &optional &default="null";
};

        global smtp_legit_watchlist: table[string] of legitVal &synchronized &redef ;
        global smtp_legit_feed="/YURT/feeds/BRO-feeds/smtp_legit_watchlist.out" &redef ;


	global interesting_sites = /@(.*\.){0,}lbl\.gov|@(.*\.){0,}es\.net|@(.*\.){0,}nersc\.gov|@(.*\.){0,}berkeley\.edu|@(.*\.){0,}cern\.ch/ &redef ; 

	global ignore_mailfrom: pattern = /=lbl.gov@lbl.gov|bounces.google.com|-bounces|\.bounces\.|\.bounces@/ ; 	

} # end of export 

#hook Notice::policy(n: Notice::Info)
#  {
#  if ( n$note == Drop::AddMortoScanner)
#    add n$actions[Notice::ACTION_DROP];
#  }


hook Notice::policy(n: Notice::Info)
{ 

	#if ( n$note == Phish::Phish) 
	#	add n$actions[Notice::ACTION_EMAIL]; 

	#if ( n$note == Phish::LabPhish) 
	#	add n$actions[Notice::ACTION_EMAIL]; 

	if ( n$note == Phish::Phish_MD5) 
		add n$actions[Notice::ACTION_EMAIL]; 

       	if ( n$note == Phish::Phish_Attachment) 
		add n$actions[Notice::ACTION_EMAIL];

       	if ( n$note == Phish::Phish_Mailfrom) 
		add n$actions[Notice::ACTION_EMAIL];

	if ( n$note == Phish::Phish_Mailto) 		
		add n$actions[Notice::ACTION_EMAIL];

	if ( n$note == Phish::Phish_from) 
		add n$actions[Notice::ACTION_EMAIL];

       	#if ( n$note == Phish::ReplyToPhish) 
	#	add n$actions[Notice::ACTION_EMAIL];

       	if ( n$note == Phish::Phish_subject) 
		add n$actions[Notice::ACTION_EMAIL];

       	if ( n$note == Phish::Phish_rcptto) 
		add n$actions[Notice::ACTION_EMAIL];

       	if ( n$note == Phish::Phish_Decoded_Subject) 
		add n$actions[Notice::ACTION_EMAIL];

       	if ( n$note == Phish::Phish_Indicator) 
		add n$actions[Notice::ACTION_EMAIL];
} 


function clean_sender(sender: string): string
{

        local pat = />|<| |\"|\'/;
        local to_n = split_string(sender,/</) ;
        local to_name: string = "" ;

	if (sender == "") 
		return to_name ; 
	
	#print fmt ("Sender is %s: %s", sender, to_n) ;
	#print fmt ("to_n: %s, |to_n|: %d", to_n, |to_n|) ;

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

event bro_init() &priority=10
{
        Input::add_table([$source=smtp_legit_feed, $name="smtp_legit_watchlist", $idx=legitIdx, $val=legitVal,  $destination=smtp_legit_watchlist, $mode=Input::REREAD]);
        Input::add_table([$source=smtp_phish_feed, $name="smtp_phish_indicators", $idx=smtp_phishIdx, $val=smtp_phishVal,  $destination=smtp_phish_indicators, $mode=Input::REREAD, 
			$pred(typ: Input::Event, left: smtp_phishIdx, right: smtp_phishVal) = 
				{ 
					right$indicator= strip(gsub(right$indicator, />|</, "")); 
					left$indicator= strip(gsub(left$indicator, />|</, "")); 
					return T;
				}  
			]);
}

event SMTP::log_smtp (rec: SMTP::Info)
{ 

	if (connection_exists(rec$id))
		local c = lookup_connection(rec$id);
	else 
		return ; 

	local mailfrom = rec?$mailfrom ? rec$mailfrom : "" ; 
	local from = rec?$from ? rec$from: "" ; 
	local reply_to = rec?$reply_to ? rec$reply_to : "" ; 




	if (interesting_sites in reply_to)
		return ; 

	if (interesting_sites in mailfrom && (reply_to == "" || interesting_sites in reply_to) )
		return ;
	
	if (ignore_mailfrom in mailfrom)
		return ; 

	### mej:
	### > > by the Ironport with $ENVELOPE_FROM != $HEADER["From:"] &&
	### > > $HEADER["From:"] =~ /\blbl\.gov$/ && $ENVELOPE_FROM !~ /\blbl\.gov$/,
	### > > and how many of those are legit vs. non-legit.

	if (( clean_sender(mailfrom) != clean_sender(from) ) && /lbl.gov|me\.com/ !in clean_sender(mailfrom) && /lbl.gov/ in clean_sender(from)) 
	{ 
		#local result = levenshtein_distance(clean_sender(from), clean_sender(mailfrom)) ;
		NOTICE([$note=LabPhish, $conn=c,  $msg=fmt("Phish: %s, %s, [reply_to: %s]", mailfrom, from, reply_to), $sub=mailfrom, $identifier=cat(mailfrom), $suppress_for=1 sec]);
	} 
	
	if ( ( clean_sender(mailfrom) == clean_sender(from) ) && /lbl\.gov|me\.com/ in clean_sender(from) && /lbl\.gov/ !in clean_sender(reply_to)) 
	{ 
		NOTICE([$note=ReplyToPhish, $conn=c,  $msg=fmt("Phish: %s, %s, [reply_to: %s]", mailfrom, from, reply_to), $sub=mailfrom, $identifier=cat(mailfrom), $suppress_for=1 sec]);
	} 
		
#	for (pi in smtp_phish_indicators)
#	{
#		### print fmt ("PI Is ::: %s", pi); 
#
#		#if (pi in from && ( clean_sender(from) != clean_sender(mailfrom)) &&  (clean_sender(from) !in smtp_legit_watchlist ) && ( clean_sender(mailfrom) !in smtp_legit_watchlist)) 
#		if (pi in from && ( clean_sender(from) != clean_sender(mailfrom)) &&  (clean_sender(from) !in smtp_legit_watchlist ) ) 
#		{
#			# print fmt ("first one: from is: %s, mailfrom: %s, cs_from: %s, cs_mailfrom: %s", from, mailfrom, clean_sender(from), clean_sender(mailfrom)); 
#
#			NOTICE([$note=Phish, $conn=c,  $msg=fmt("Phish: %s, %s, [reply_to: %s], [Subject: %s]", mailfrom, from, reply_to, rec$subject), 
#					$sub=rec$mailfrom, $identifier=cat(mailfrom), $suppress_for=1 sec]);
#			#print fmt ("PI2 Is ::: %s", pi); 
#		} 
#	 
#		if ( rec?$reply_to  && reply_to != "" )
#		{
#
#				if (pi in reply_to && ( reply_to !in smtp_legit_watchlist) && interesting_sites !in reply_to) 
#				{ 
#					#print fmt ("PI3 Is ::: %s", pi); 
#					NOTICE([$note=Phish, $conn=c,  $msg=fmt("Phish: %s, %s, [reply_to: %s]", mailfrom, from, reply_to), $sub=rec$mailfrom, $identifier=cat(mailfrom), $suppress_for=1 sec]);
#				} 
#		} 
#	}

}  # end of policy 
