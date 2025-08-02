# netdisco-meraki - Cisco Meraki to Netdisco Import Tool
This plugin is to import data from Cisco Meraki into Netdisco. Currently it is able to pull basic Device (MX,MR,MS,Z tested), and Client devices (just the arp:ip relations) into Netdisco. 

## Installation
1. Copy the contents of nd-site-local/* into your nd-site-local folder structure (Our deployment is docker, so this is [toplevel]/netdisco/nd-site-local/...)
2. Add the contents of deployment/deployment.yml to your deployment.yml and update the api_key and org_id settings.
3. This currently is ran via 'netdisco-do merakisync' (or docker compose run netdisco-do merakisync)

## Todo
1. Integrate with netdisco scheduling
2. Fully populate device table with all avaliable info from meraki)
3. Fully populate clients table with meraki info (Including Switchport/Wlan)
4. Device topology using neighbors (MS appears to provide this, MX doesnt?, need to dig deeper into api).


