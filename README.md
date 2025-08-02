# netdisco-meraki - Cisco Meraki to Netdisco Import Tool
This plugin is to import data from Cisco Meraki into Netdisco. Currently it is able to pull basic Device (MX,MR,MSW,Z tested), and Client devices (just the arp:ip relations) into Netdisco. 

- Installation
Copy the contents of nd-site-local/* into your nd-site-local folder structure (Our deployment is docker, so this is [toplevel]/netdisco/nd-site-local/...)
Add the contents of deployment/deployment.yml to your deployment.yml and update the api_key and org_id settings.

- Notes


