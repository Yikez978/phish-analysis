module Phish;

export {

	global isRareURLClick : function(domain: string): bool ; 
	global isHistoricallyNewAttacker : function(domain: string, from_name: string, from_address: string): bool ; 
	global isSpoofworthyFromName : function(from_name: string ): bool ; 
	global isNameSpoofer : function(domain: string, from_name: string,  full_from: string): bool ; 
	global isSpoofworthyFromAddress : function(from_address: string): bool ;
	global isAddressSpoofer : function(domain: string, from_address: string, full_from: string ): bool ; 

} 

function isRareURLClick(domain: string): bool 
{

       # the paper the definition we used:
        # If a domain has been seen fewer than 3 times in previous
        # HTTP clicks, it is rare.
        # If a domain has been seen at least 3 times in prior HTTP
        # traffic, and the time of the 3rd visit was more than 3 days
        # ago, it is rare.
        # Otherwise, it is not-rare.
        #if (domain in http_fqdn && ( (|http_fqdn[domain]$days_visited| >= 3 && (network_time() - http_fqdn[domain]$days_visited[3] > 3 days)) || (http_fqdn[domain]$num_requests < 3)))

        if (domain in http_fqdn && (((network_time() - http_fqdn[domain]$days_visited[0] ) < 3 days ) || (http_fqdn[domain]$num_requests < 3)))
	{ 
		return T; 
	} 

	return F; 
} 


function isHistoricallyNewAttacker(domain: string, from_name: string, from_address: string): bool 
{	

# - *Historically New Attacker*
#	generate alert for historically new attacker
#      - if (RareURLClick && *from_name:days_sent <= 2* && *from_email_addr:days_sent  <= 2*)

	if (isRareURLClick(domain) && |smtp_from_name[from_name]$days_sent| <= 2 && |smtp_from_email[from_address]$days_sent| <= 2) 
	{ 
		return T ; 
	} 

	return F ; 

}
########### from_name #################
# smtp_from_name 
#Frank Zuidema -> [days_sent=[1481050625.922146], email={\x0afzuidema@lbl.gov\x0a}, emails_sent=4, interesting=F]

function isSpoofworthyFromName(from_name: string ): bool 
{

#	- SpoofworthyFromName is a boolean OR-clause where:
#         (from_name:days_sent >= 14 || from_name:num_clicks > 1 || from_name:emails_recv > 1)
	
	if (|smtp_from_name[from_name]$days_sent| >= 14 || smtp_from_name[from_name]$num_clicks > 1 || smtp_from_name[from_name]$emails_recv > 1) 
		return T ; 
	
	return F; 

} 

########### smtp_from #################
# smtp_from 
#Frank Zuidema <fzuidema@lbl.gov> -> [days_sent=[1481050625.922146], email={\x0afzuidema@lbl.gov\x0a}, emails_sent=4, interesting=F]

function isNameSpoofer(domain: string, from_name: string,  full_from: string): bool 
{

# *Name spoofer* 
#	- generate alert for rare name spoofer
#  - if (RareURLClick && *SpoofworthyFromName* && *full_from_field:days_sent <= 1*)

	if (isRareURLClick(domain) && isSpoofworthyFromName(from_name) && |smtp_from[full_from]$days_sent| <= 1)
		return T;

	return F ; 
} 

########### from_email #################
# smtp_from_email 
#fzuidema@lbl.gov -> [days_sent=[1481050625.922146], name={\x0aFrank Zuidema\x0a}, emails_sent=4, interesting=F]


function isSpoofworthyFromAddress(from_address: string): bool
{

#         - To compute mail_from:days_sent, we can simply take the MAILFROM
#         header in the current alert's email and look up its value in the mail_from table
#         - (The paper's criteria is a bit more complicated, but we can ignore the extra stuff for now)


#         - SpoofworthyFromAddress is a boolean OR-clause where:
#         (from_address:days_sent >= 14 || from_address:num_clicks > 1 || from_address:emails_recv > 1)


	if (|smtp_from_email[from_address]$days_sent| >= 14 || smtp_from_email[from_address]$num_clicks > 1 || smtp_from_email[from_address]$emails_recv > 1)
		return T ;

	return F ; 

} 

########### smtp_from #################
# smtp_from 
#Frank Zuidema <fzuidema@lbl.gov> -> [days_sent=[1481050625.922146], email={\x0afzuidema@lbl.gov\x0a}, emails_sent=4, interesting=F]

function isAddressSpoofer(domain: string, from_address: string, full_from: string ): bool 
{ 
# *Address spoofer*
# 	generate alert for rare address spoofer
#   	- if (RareURLClick && *SpoofworthyFromAddress* && *mail_from:days_sent <= 1*)

	if (isRareURLClick(domain) && isSpoofworthyFromAddress(from_address) && |smtp_from[full_from]$days_sent| <= 1)
		return T ; 

	return F; 
}


##### relevant data structures  ########
# http_fqdn: 
#lbl.gov.invoicenotices.com  - [days_visited=[1481051156.986024, 1481062180.295358], num_requests=48, last_visited=1481062276.631609, interesting=T]
#google.com  - [days_visited=[1481062158.249375], num_requests=2, last_visited=1481062158.249375, interesting=T]
########### from_name #################
# smtp_from_name 
#Frank Zuidema -> [days_sent=[1481050625.922146], email={\x0afzuidema@lbl.gov\x0a}, emails_sent=4, interesting=F]
########### from_email #################
# smtp_from_email 
#fzuidema@lbl.gov -> [days_sent=[1481050625.922146], name={\x0aFrank Zuidema\x0a}, emails_sent=4, interesting=F]
########### smtp_from #################
# smtp_from 
#Frank Zuidema <fzuidema@lbl.gov> -> [days_sent=[1481050625.922146], email={\x0afzuidema@lbl.gov\x0a}, emails_sent=4, interesting=F]
########################################
