#!/bin/bash
#
# GRAPE
#

# User Variables
################
# Change and update these as requried
#
# API Keys
##########
#
# API Key For https://api.shodan.io
SHODAN_API=""
# API Key for https://otx.alienvault.com
OTX_API=""
# API Key for https://www.virustotal.com
VT_API=""
#

# Local System Variables
########################
# You can change these if you'd like

# URL Variables
###############
# You shouldn't have to change these but you might
# if the providers change their layouts in the
# future
#
########################
# Shodan Configuration #
########################
# Shodan URL
SHODAN_BASE="https://api.shodan.io"
# Shodan API Root
SHODAN_ROOT="/shodan/"
# Shodan Header
SHODAN_TAIL="?key=$SHODAN_API"
#
#########################
# IP Addresses/Host (shodan/host/$IP_ADDR)
SHODAN_HOST="host/"
#
#
#####################
# OTX Configuration #
#####################
# OTX URL
OTX_BASE="https://otx.alienvault.com"
# OTX API Root
OTX_ROOT="/api/v1/indicators/"
# OTX Header
OTX_HEADER="X-OTX-API-KEY: $OTX_API"
#
# OTX API Builder
#################
# IP Addresses (IPv4/$IP_ADDR/general)
OTX_IPV4_BASE="IPv4/"
OTX_IPV4_GENERAL="/general"
#
# IPv6 Addresses (IPv6/$IP_ADDR/general)
OTX_IPV6_BASE="IPv6"
OTX_IPV6_GENERAL="/general"
#
# Hostname Information (hostname/$HOSTNAME/$SECTION)
OTX_HOSTNAME_BASE="hostname/"
#
# File Information (file/$HASH/$SECTION [general or analysis])
OTX_FILE_BASE="file/"
#
#
#############################
# Virus Total Configuration #
#############################
# Virus Total URL
VT_BASE="https://www.virustotal.com"
# Virus Total API Root
VT_ROOT="/api/v3/"
# Virus Total Header
VT_HEADER="x-apikey: $VT_API"
#
# Virus Total Domain Limit - Default 25
# Increasing this /may/ break things
VT_DOMAIN_LIMIT="25"
# Virus Total File Limit - Default 100
VT_FILE_LIMIT="100"
# Virus Total API Builder
#########################
# IP Addresses (ip_addresses/$IP_ADDR/sub_item)
VT_IP_BASE="ip_addresses/"
VT_IP_COLLECTIONS="/collections"
VT_IP_RESOLUTIONS="/resolutions"
VT_IP_COMFILES="/communicating_files"
VT_IP_COMMENTS="/comments"
#
# File Behaviours (files/$ID/behaviours)
VT_FILE_BEHAVIOURS_BASE="file_behaviours/"
VT_FILE_BEHAVIOURS_FILE="/file"


# Functions Start Here
######################

function reqcheck() {
	# Check to make sure we have the pre-requisites
	echo "Check stuff"
}

function ipv4() {
	# Run checks on IP address
	# Set Variables

	# Temporary Output File $OF
	OF=/tmp/ip.json

	# Temporary Second Output File $OF2
	OF2=/tmp/file.json

	# Final Output File $FF
	FF=/tmp/output.file

	OTX_IP_PULSE_COUNT=0
	OTX_FILE_PULSE_COUNT=0
	OTX_PULSE_TOTAL=0

	echo "" > $FF

	echo "" | tee -a $FF
	echo -n "Checking IP Address: $1" | tee -a $FF
	OTX_IP_PULSE_COUNT=$(curl -s -H "$OTX_HEADER" "$OTX_BASE$OTX_ROOT$OTX_IPV4_BASE$1$OTX_IPV4_GENERAL" | jq -r '.pulse_info.count')
	echo -e "\e[31m OTX Pulse Count: $OTX_IP_PULSE_COUNT\e[0m" | tee -a $FF
	let OTX_PULSE_TOTAL=$OTX_IP_PULSE_COUNT+$OTX_PULSE_TOTAL
	echo "" | tee -a $FF
	echo -n "Searching (maximum) $VT_DOMAIN_LIMIT domains from VirusTotal..." | tee -a $FF
	curl -s -H "$VT_HEADER" "$VT_BASE$VT_ROOT$VT_IP_BASE$1$VT_IP_RESOLUTIONS?limit=$VT_DOMAIN_LIMIT" > $OF
	echo "Found $(jq '.data[].attributes.host_name' $OF | wc -l) domain(s)" | tee -a $FF
	x=0
	cc=0
	dd=0
	ee=0
	ff=0
	gg=0
	for i in $(jq -r '.data[].attributes.host_name' $OF); do
		c=0
		d=0
		e=0
		f=0
		g=0

		echo -e "\e[4m$i: \e[0m" | tee -a $FF
		for j in $(jq -r ".data[$x].attributes.date" $OF); do
			echo -e "   \e[95mResolution Date: $(date -d @$j)\e[0m" | tee -a $FF
		done
		for k in $(jq -r ".data[$x].attributes.host_name_last_analysis_stats.harmless" $OF); do
			echo -e "   \e[32mHarmless: $k\e[0m" | tee -a $FF
			let cc=$cc+$k
		done
		for l in $(jq -r ".data[$x].attributes.host_name_last_analysis_stats.malicious" $OF); do
			echo -e "   \e[31mMalicious: $l\e[0m" | tee -a $FF
			let dd=$dd+$l
		done
		for m in $(jq -r ".data[$x].attributes.host_name_last_analysis_stats.suspicious" $OF); do
			echo -e "   \e[33mSuspicious: $m\e[0m" | tee -a $FF
			let ee=$ee+$m
		done
		for n in $(jq -r ".data[$x].attributes.host_name_last_analysis_stats.undetected" $OF); do
			echo -e "   \e[34mUndetected: $n\e[0m" | tee -a $FF
			let ff=$ff+$n
		done
		for o in $(jq -r ".data[$x].attributes.host_name_last_analysis_stats.timeout" $OF); do
			echo -e "   \e[94mTimed-Out: $o\e[0m" | tee -a $FF
			let gg=$gg+$o
		done
		OTX_HOSTNAME_PULSE_COUNT=$(curl -s -H "$OTX_HEADER" "$OTX_BASE$OTX_ROOT$OTX_DOMAIN_BASE$i/general" | jq -r '.pulse_info.count')
		echo -e "   \e[31mOTX Pulse(s): $OTX_HOSTNAME_PULSE_COUNT\e[0m" | tee -a $FF
		let OTX_PULSE_TOTAL=$OTX_HOSTNAME_PULSE_COUNT+$OTX_PULSE_TOTAL
		echo | tee -a $FF

		let x=$x+1
	done

	echo "" | tee -a $FF

	echo -n "Searching (maximum) $VT_FILE_LIMIT communicating files on VirusTotal..." | tee -a $FF
	curl -s -H "$VT_HEADER" "$VT_BASE$VT_ROOT$VT_IP_BASE$1$VT_IP_COMFILES?limit=$VT_FILE_LIMIT" > $OF
	echo "Found $(jq '.data[].attributes.vhash' $OF | wc -l)/100 file(s) communicating with $1" | tee -a $FF

	x=0
	aa=0
	bb=0
	for i in $(jq -r '.data[].attributes.sha256' $OF); do
		a=0
		b=0
				
		echo -en "\e[4msha256 - $i:\e[0m" | tee -a $FF
		for j in $(jq -r ".data[$x].attributes.last_analysis_results[].category" $OF); do
			if [ "$j" == "malicious" ]; then
				let a=$a+1
				let aa=$aa+1
			else
				let b=$b+1
				let bb=$bb+1
			fi
		done
		echo -en "   \e[31mMalicious: $a\e[0m" | tee -a $FF
		echo -en "   \e[32mUndetected: $b\e[0m" | tee -a $FF
		OTX_FILE_PULSE_COUNT=$(curl -s -R "$OTX_HEADER" "$OTX_BASE$OTX_ROOT$OTX_FILE_BASE$i/general" | jq -r '.pulse_info.pulses | .[] | .name' | wc -l)
		echo -en "   \e[34mOTX Pulse(s): $OTX_FILE_PULSE_COUNT\e[0m"
		let OTX_PULSE_TOTAL=$OTX_PULSE_TOTAL+$OTX_FILE_PULSE_COUNT
		# echo -en "   \e[34mOTX Pulse(s): $(curl -s -H \"$OTX_HEADER\" \"$OTX_BASE$OTX_ROOT$OTX_FILE_BASE$i/general\" | jq -r '.pulse_info.pulses | .[] | .name' | wc -l | tee -a $FF) \e[0m"
		echo | tee -a $FF
		let x=$x+1
	done

	# Begin Shodan
	echo | tee -a $FF
	echo -n "Checking $1 on Shodan..." | tee -a $FF
	curl -s "$SHODAN_BASE$SHODAN_ROOT$SHODAN_HOST$1$SHODAN_TAIL" > $OF
	echo "Done." | tee -a $FF
	echo "City: $(jq -r '.city' $OF)" | tee -a $FF
	echo "Country: $(jq -r '.country_name' $OF)" | tee -a $FF
	echo "Hostnames: " 
	x=0
	for i in $(jq -r '.hostnames[]' $OF); do
		echo $(jq -r ".hostnames[$x]" $OF)
		let x=$x+1
	done
	echo "Open Ports: "

	x=0
	for i in $(jq -r '.data[].port' $OF); do
		echo -n " " $(jq -r ".data[$x].port" $OF) | tee -a $FF
		echo " " $(jq -r ".data[$x].product" $OF) | tee -a $FF
		let x=$x+1
	done

	# Provide Score Here
	echo | tee -a $FF
	echo -e "\e[4mScores\e[0m" | tee -a $FF
	echo "   Domain Score for $1" | tee -a $FF
	echo -e "   \e[32mHarmless: $cc\e[0m \e[31mMalicious: $dd\e[0m \e[33mSuspiciouss: $ee\e[0m \e[34mUndetected: $ff\e[0m \e[94mTimed-Out: $ee\e[0m" | tee -a $FF
	echo | tee -a $FF
	echo "   File Score for $1" | tee -a $FF
	echo -e "   \e[32mUndetected: $bb\e[0m \e[31mMalicious: $aa\e[0m" | tee -a $FF
	echo | tee -a $FF
	echo -e "   OTX Pulses for $1: \e[31m$OTX_PULSE_TOTAL\e[0m" | tee -a $FF
	echo | tee -a $FF

}

function ipv6() {
	# Run checks on IP address
	# Set Variables

	# Temporary Output File $OF
	OF=/tmp/ip.json

	# Temporary Second Output File $OF2
	OF2=/tmp/file.json

	# Final Output File $FF
	FF=/tmp/output.file

	OTX_IP_PULSE_COUNT=0
	OTX_FILE_PULSE_COUNT=0
	OTX_PULSE_TOTAL=0

	echo "" > $FF

	echo "" | tee -a $FF
	echo -n "Checking IP Address: $1" | tee -a $FF
	OTX_IP_PULSE_COUNT=$(curl -s -H "$OTX_HEADER" "$OTX_BASE$OTX_ROOT$OTX_IPV6_BASE$1$OTX_IPV6_GENERAL" | jq -r '.pulse_info.count')
	echo -e "\e[31m OTX Pulse Count: $OTX_IP_PULSE_COUNT\e[0m" | tee -a $FF
	let OTX_PULSE_TOTAL=$OTX_IP_PULSE_COUNT+$OTX_PULSE_TOTAL
	echo "" | tee -a $FF
	##########################################################
	echo "VirusTotal IPv6 not available at the moment."
	##########################################################
	
	# echo -n "Searching (maximum) $VT_DOMAIN_LIMIT domains from VirusTotal..." | tee -a $FF
	# curl -s -H "$VT_HEADER" "$VT_BASE$VT_ROOT$VT_IP_BASE$1$VT_IP_RESOLUTIONS?limit=$VT_DOMAIN_LIMIT" > $OF
	# echo "Found $(jq '.data[].attributes.host_name' $OF | wc -l) domain(s)" | tee -a $FF
	# x=0
	# cc=0
	# dd=0
	# ee=0
	# ff=0
	# gg=0
	# for i in $(jq -r '.data[].attributes.host_name' $OF); do
	# 	c=0
	# 	d=0
	# 	e=0
	# 	f=0
	# 	g=0

	# 	echo -e "\e[4m$i: \e[0m" | tee -a $FF
	# 	for j in $(jq -r ".data[$x].attributes.date" $OF); do
	# 		echo -e "   \e[95mResolution Date: $(date -d @$j)\e[0m" | tee -a $FF
	# 	done
	# 	for k in $(jq -r ".data[$x].attributes.host_name_last_analysis_stats.harmless" $OF); do
	# 		echo -e "   \e[32mHarmless: $k\e[0m" | tee -a $FF
	# 		let cc=$cc+$k
	# 	done
	# 	for l in $(jq -r ".data[$x].attributes.host_name_last_analysis_stats.malicious" $OF); do
	# 		echo -e "   \e[31mMalicious: $l\e[0m" | tee -a $FF
	# 		let dd=$dd+$l
	# 	done
	# 	for m in $(jq -r ".data[$x].attributes.host_name_last_analysis_stats.suspicious" $OF); do
	# 		echo -e "   \e[33mSuspicious: $m\e[0m" | tee -a $FF
	# 		let ee=$ee+$m
	# 	done
	# 	for n in $(jq -r ".data[$x].attributes.host_name_last_analysis_stats.undetected" $OF); do
	# 		echo -e "   \e[34mUndetected: $n\e[0m" | tee -a $FF
	# 		let ff=$ff+$n
	# 	done
	# 	for o in $(jq -r ".data[$x].attributes.host_name_last_analysis_stats.timeout" $OF); do
	# 		echo -e "   \e[94mTimed-Out: $o\e[0m" | tee -a $FF
	# 		let gg=$gg+$o
	# 	done
	# 	OTX_HOSTNAME_PULSE_COUNT=$(curl -s -H "$OTX_HEADER" "$OTX_BASE$OTX_ROOT$OTX_DOMAIN_BASE$i/general" | jq -r '.pulse_info.count')
	# 	echo -e "   \e[31mOTX Pulse(s): $OTX_HOSTNAME_PULSE_COUNT\e[0m" | tee -a $FF
	# 	let OTX_PULSE_TOTAL=$OTX_HOSTNAME_PULSE_COUNT+$OTX_PULSE_TOTAL
	# 	echo | tee -a $FF

	# 	let x=$x+1
	# done

	# echo "" | tee -a $FF

	# echo -n "Searching (maximum) $VT_FILE_LIMIT communicating files on VirusTotal..." | tee -a $FF
	# curl -s -H "$VT_HEADER" "$VT_BASE$VT_ROOT$VT_IP_BASE$1$VT_IP_COMFILES?limit=$VT_FILE_LIMIT" > $OF
	# echo "Found $(jq '.data[].attributes.vhash' $OF | wc -l)/100 file(s) communicating with $1" | tee -a $FF

	# x=0
	# aa=0
	# bb=0
	# for i in $(jq -r '.data[].attributes.sha256' $OF); do
	# 	a=0
	# 	b=0
				
	# 	echo -en "\e[4msha256 - $i:\e[0m" | tee -a $FF
	# 	for j in $(jq -r ".data[$x].attributes.last_analysis_results[].category" $OF); do
	# 		if [ "$j" == "malicious" ]; then
	# 			let a=$a+1
	# 			let aa=$aa+1
	# 		else
	# 			let b=$b+1
	# 			let bb=$bb+1
	# 		fi
	# 	done
	# 	echo -en "   \e[31mMalicious: $a\e[0m" | tee -a $FF
	# 	echo -en "   \e[32mUndetected: $b\e[0m" | tee -a $FF
	# 	OTX_FILE_PULSE_COUNT=$(curl -s -R "$OTX_HEADER" "$OTX_BASE$OTX_ROOT$OTX_FILE_BASE$i/general" | jq -r '.pulse_info.pulses | .[] | .name' | wc -l)
	# 	echo -en "   \e[34mOTX Pulse(s): $OTX_FILE_PULSE_COUNT\e[0m"
	# 	let OTX_PULSE_TOTAL=$OTX_PULSE_TOTAL+$OTX_FILE_PULSE_COUNT
	# 	# echo -en "   \e[34mOTX Pulse(s): $(curl -s -H \"$OTX_HEADER\" \"$OTX_BASE$OTX_ROOT$OTX_FILE_BASE$i/general\" | jq -r '.pulse_info.pulses | .[] | .name' | wc -l | tee -a $FF) \e[0m"
	# 	echo | tee -a $FF
	# 	let x=$x+1
	# done

	##########################################################
	echo "VirusTotal IPv6 end"
	##########################################################

	# Begin Shodan
	echo | tee -a $FF
	echo -n "Checking $1 on Shodan..." | tee -a $FF
	curl -s "$SHODAN_BASE$SHODAN_ROOT$SHODAN_HOST$1$SHODAN_TAIL" > $OF
	echo "Done." | tee -a $FF
	echo "City: $(jq -r '.city' $OF)" | tee -a $FF
	echo "Country: $(jq -r '.country_name' $OF)" | tee -a $FF
	echo "Hostnames: " 
	x=0
	for i in $(jq -r '.hostnames[]' $OF); do
		echo $(jq -r ".hostnames[$x]" $OF)
		let x=$x+1
	done
	echo "Open Ports: "

	x=0
	for i in $(jq -r '.data[].port' $OF); do
		echo -n " " $(jq -r ".data[$x].port" $OF) | tee -a $FF
		echo " " $(jq -r ".data[$x].product" $OF) | tee -a $FF
		let x=$x+1
	done

	# Provide Score Here
	echo | tee -a $FF
	echo -e "\e[4mScores\e[0m" | tee -a $FF
	echo "   Domain Score for $1" | tee -a $FF
	echo -e "   \e[32mHarmless: $cc\e[0m \e[31mMalicious: $dd\e[0m \e[33mSuspiciouss: $ee\e[0m \e[34mUndetected: $ff\e[0m \e[94mTimed-Out: $ee\e[0m" | tee -a $FF
	echo | tee -a $FF
	echo "   File Score for $1" | tee -a $FF
	echo -e "   \e[32mUndetected: $bb\e[0m \e[31mMalicious: $aa\e[0m" | tee -a $FF
	echo | tee -a $FF
	echo -e "   OTX Pulses for $1: \e[31m$OTX_PULSE_TOTAL\e[0m" | tee -a $FF
	echo | tee -a $FF

}

function usage() {
	echo "Usage"
	echo "-----"
	echo "./grape.sh [switch] [source]"
	echo
	echo "Switches"
	echo "--------"
	echo "   -4: Provide an IPv4 address to investigate"
	echo "   -6: Provide an IPv6 address to investigate"
	echo
	exit 1
}

# Main Program Starts Here
##########################
#clear
if [ $# -lt 2 ]; then
	usage
fi

case "$1" in
	"-4")
		ipv4 "$2"
		;;
	"-6")
		ipv6 "$2"
		;;
	*)
		usage
		;;
esac

# EOF
