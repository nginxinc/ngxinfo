#!/usr/bin/env python3

## build.py (c) NGINX, Inc. [10/6/2021] Timo Stark <t.stark@f5.com>
## Build script for nginxinfo v0.0.1 alpha

import xml.etree.ElementTree as ET
import requests
import zipfile
from pathlib import Path
import re
from bs4 import BeautifulSoup
from datetime import date


build=date.today()

modules_url='http://hg.nginx.org/pkg-oss/archive/tip.zip/rpm/SPECS/'
xml= requests.get('http://hg.nginx.org/nginx.org/raw-file/tip/xml/en/security_advisories.xml')

r = requests.get(modules_url, allow_redirects=True)
with open('modules.zip', 'wb') as mfile:
  mfile.write(r.content)
  mfile.close()


with zipfile.ZipFile('modules.zip', 'r') as mzip:
  mzip.extractall('./modules')
 

m = ""

for path in Path('./modules').rglob('Makefile.module*'):
  with open(f"{path.parent}/{path.name}", 'r') as mf:
       for line in mf:
         if re.search("load_module", line):
           m+= line.rsplit('/', 1)[-1]
  mf.close()


d = set()
rd = requests.get('http://nginx.org/en/docs/dirindex.html')
soup = BeautifulSoup(rd.content, 'html.parser')
container = soup.find('div', id='content')

for link in container.find_all('a'):
  d.add(link.string)

de = list(d)
de.sort()
de = '\n'.join(de)

root = ET.fromstring(xml.text)
s = ""
for item in root[0][2]:
  if (any(x in item.get('vulnerable') for x in ['Windows', 'all'] )):
    continue
  if (',' in item.get('vulnerable') ) :
     split = item.get('vulnerable').split(',')
     for sub in split:
      s+= ";".join([item.get('cve'), sub.strip(), item.get('good').replace(" ",""), item.get('name'), "\n"])
  else :
     s+= ";".join([item.get('cve'), item.get('vulnerable').strip(), item.get('good').replace(" ",""), item.get('name'), "\n"])


bash_awk = """
ngx::parse_configuration() {
	FUNCTION='
"""

bash_awk_end = """
'
   [[ $RUNLEVEL == 99 ]] && awk "$FUNCTION" config1.tmp || awk "$FUNCTION" config1.tmp > /dev/null 2>&1
}
"""

bash_vars = r"""
## build.py (c) NGINX, Inc. [10/6/2021] Timo Stark <t.stark@f5.com>
## Build script for nginxinfo v0.0.1 alpha

COLGREEN=$(tput setaf 2)
COLYELLOW=$(tput setaf 3)
COLRED=$(tput setaf 1)
COLRES=$(tput sgr0)

NGXV=""
NGINXIFOVERSION="nginxinfo v0.1 alpha"
NGXVERSION=$(nginx -v 2>&1 |awk 'match($0, /[0-9]+(\.[0-9]+)+/, a) {print a[0]}')
OPENSSLVERSION=$(openssl version)
HOSTINFORMATION=$(cat /etc/os-release | tr '\n' '^' | tr -d '"')
NGXRUNSTATE=1
DIRERRORCNT=1
RUNLEVEL=""
EXITCODE=0
FOUND=0;
NFOUND=0;
MNFOUND=0;
CVEFOUND=0;
"""

bash_main_functions = r"""
declare -A NGINXINFO
declare -A HOSTINFO
declare -A CONFIGURATION
declare -A CVES

main::preflight() {
  #is NGINX in the system path?
  NGXV=$(nginx -V 2>&1)
  if [ $? -ne 0 ]; then
    echo "The NGINX binary wasn't found. Exiting!";
	exit 99
  fi
}


sys::hostinfo() {
  eval HOSTINFO=($(awk -v "hostinfo=$HOSTINFO" '{split($0, a, "^");
		    for ( i in a ) {
	          split(a[i], b, "=");
			  if (b[1] != "") {
			    printf "[\"%s\"]=\"%s\"\n", b[1], b[2];
			  }
		    }
        }' <<< $HOSTINFORMATION ));
}

ngx::instance_information() {

eval NGINXINFO=($(awk -v "nginxinfo=$NGINXINFO" '{split($0, a, "--");
         for ( i in a )
           {
	        split(a[i], b, "=");
			printf "[\"%s\"]=\"%s\"\n", b[1], b[2];
           }
        }' <<< $NGXV ));	
}

main::helpscreen() {
## Todo: Display Modules from Mac "/usr/local/lib/unit/modules/" and Linux System
	
	[[ $1 == 9 ]] && echo "${COLRED}Command not found!${COLRES}"
	
	echo "USAGE: $COMMAND [options]"
	echo ""
	echo " NGINX Info for $(uname -s). NGINX Version $NGXVERSION"
	echo " running instance detected: ${NGINXINFO[build]} / ${NGINXINFO[pid-path]} "
	echo " Options:"
    echo " -h | --help                            # Print this helpscreen"
    echo " -v | --verbose                         # Show all information found"
	exit 1	
}

ngx::ngx_config_writer() {
	echo "# include $1" >> $2
	cat $(echo $1 |tr -d ';') >> $2
}

ngx::finder() {
	configinc=$(echo "$1" |awk '{if ($1 == "include"){print $2} else {exit 1}}')
	if [ $? -eq 0 ]; then
		if [[ $configinc == /* ]]; then
		  ngx::ngx_config_writer $configinc "config1.tmp"
        else
		  ngx::ngx_config_writer "${NGINXINFO[conf-path]%/*}/$configinc" "config1.tmp"
		fi
	else
		echo "$1" >> config1.tmp
	fi
}

ngx::include_test() {
	rm config1.tmp;
	while IFS= read -r line ; do ngx::finder "$line"; done <<< "$1"
}

ngx::directives() {
  for i in `cat ./config.tmp | tr -d '\t\n{}' | tr ';' '\n' | grep -v '#' | awk '{print $1}'`; do
    if [[ $i != *['!'*@#\$%^\&*()+\=\"]* ]]; then
      [[ ${CONFIGURATION[$i]+_} ]] && CONFIGURATION[$i]=$((${CONFIGURATION[$i]}+1)) || CONFIGURATION[$i]=1
    fi
  done
}

ngx::directives_verbose() {
	for x in "${!CONFIGURATION[@]}"; do printf "[%s]=%s\n" "$x" "${CONFIGURATION[$x]}" ; done
	echo "We have found ${#CONFIGURATION[@]} unique directives in use";
}

ngx::cve() {
    
	while read line; do
		 VULNERABLE=$(echo $line |awk '{ split($0,a,";"); print a[2]}')
		 GOOD=$(echo $line |awk '{ split($0,a,";"); print a[3] }' | tr -d '+')
		 CVE=$(echo $line |awk '{ split($0,a,";"); print a[1] }')

		 if [ `echo $VULNERABLE"-"$NGXVERSION | tr '-' '\n' | sort -Vr | head -1` != $NGXVERSION ]; then
		   if [ `echo $VULNERABLE"-"$NGXVERSION | tr '-' '\n' | sort -V | head -1` == $NGXVERSION ]; then
			  continue
		   fi
           SKIP=0
		   #checking the good values
		   MESSAGE="CVE Found $CVE"
		   IFS=', ' read -r -a array <<< "$GOOD"

		   for i in "${!array[@]}"
		   do
			  if [ `echo "${array[$i]}-$NGXVERSION" |tr '-' '\n' | sort -Vr | head -1` == $NGXVERSION ]; then
				MESSAGE=""
                SKIP=1
			  fi
		   done
		   if [[ $CVEFOUND -eq 0 ]]; then echo "   nginx-$NGXVERSION is affected by: "; fi
		   ((++CVEFOUND))
		   if [[ $RUNLEVEL -gt 9 ]] && [[ $SKIP -eq 0 ]]; then echo "    - ${COLYELLOW}$MESSAGE${COLRES}"; fi
		 fi
	done <<< $CVELIST
	
	if [[ $CVEFOUND -eq 0 ]] && [[ $RUNLEVEL -gt 9 ]]; then echo "   ** Nothing found **  "; fi
}

ngx::module_check() {
  if [ -f "./module-config.tmp" ]; then
	echo "$ALLMODULES" > allmodules.txt
	while read m; do
	if grep -Fqx "${m##*/}" allmodules.txt; then
		   [[ $RUNLEVEL == 99 ]] && echo ${COLGREEN}"Found $m"${COLRES}
		   ((++FOUND))
		else
		   if [[ $MNFOUND -eq 0 ]] && [[ $RUNLEVEL -gt 9 ]]; then echo "  - Found unsupoported modules: "; fi
		     [[ $RUNLEVEL -gt 9 ]] && echo ${COLRED}"    - ${m##*/}"${COLRES}
		     ((++MNFOUND))
		fi
	done < module-config.tmp | tr -d '"' | tr -d "'" | tr -d ";"
  fi  
}

ngx::directive_check() {
	 echo -e "$ALLDIRECTIVES" > alldirs.txt
	 for x in "${!CONFIGURATION[@]}"; do
		if grep -Fxq "$x" alldirs.txt; then
			[[ $RUNLEVEL == 99 ]] && echo ${COLGREEN}"Found $x ${CONFIGURATION[$x]}x${COLRES}" ;((++FOUND))
		else
			if [[ $NFOUND -eq 0 ]] && [[ $RUNLEVEL -gt 9 ]]; then echo "  - Found unsupoported directives: "; fi
			[[ $RUNLEVEL -gt 9 ]] && echo ${COLRED}"    - $x (x${CONFIGURATION[$x]})${COLRES}" ;((++NFOUND))
		fi
	done
    if [[ $RUNLEVEL -gt 9 ]] && [[ $NFOUND -eq 0 ]]; then echo "${COLGREEN}  No unknown directives found. ${COLRES}"; fi
}

sys::net() {
   if [[ $RUNLEVEL -eq 99 ]] && [[ $NGXRUNSTAT -ne 0 ]]; then
	grep -v "rem_address" /proc/$NGXPID/net/tcp  | awk 'function hextodec(str,ret,n,i,k,c){
		ret = 0
		n = length(str)
		for (i = 1; i <= n; i++) {
			c = tolower(substr(str, i, 1))
			k = index("123456789abcdef", c)
			ret = ret * 16 + k
		}
		return ret
	} {x=hextodec(substr($2,index($2,":")-2,2)); for (i=5; i>0; i-=2) x = x"."hextodec(substr($2,i,2))}{print x":"hextodec(substr($2,index($2,":")+1,4))}'
  fi
}

main::exitcode() {
# 0 = OK
# 10 = WARNING
# 50 = ERRORS
# 99 = EXCEPTION
# 
# FOUND=0;
# NFOUND=0;
# CVEFOUND=0;
# MNFOUND=0;
 if [[ $RUNLEVEL -gt 9 ]]; then
  echo ""
  echo "  Summary"
  echo "  -------"
 fi 
  
  if [ $EXITCODE -eq 0 ]; then
 	if [[ $CVEFOUND -gt 0 ]]; then
 	  EXITCODE=10
 	fi
 	
    if [[ $NFOUND -gt 0 ]] || [[ $MNFOUND -gt 0 ]]; then
 	 
 	  EXITCODE=50
 	fi	
  else
 	EXITCODE=99
  fi

  case $EXITCODE in
    0)
     if [[ $RUNLEVEL -gt 9 ]]; then echo "${COLGREEN}  Congratulations! No warnings or errors found! You are good upgrading to NGINX Plus.${COLRES}"; fi
     ;;
   10)
     if [[ $RUNLEVEL -gt 9 ]]; then echo "${COLYELLOW} There are warnings but you are good upgrading to NGINX Plus. Congratulations!"; fi
   ;;
   50)
    if [[ $RUNLEVEL -gt 9 ]]; then echo "${COLRED}  Do not upgrade${COLRES} to NGINX Plus without first discussing this project with your F5/NGINX representative"; fi
   ;;
   *)
    if [[ $RUNLEVEL -gt 9 ]]; then echo "${COLRED}  An error occured!${COLRES} Please contact your F5/NGINX representative"; fi
   ;;
  esac

 exit $EXITCODE
}

main::run() {
	
	NGXPID=$(cat ${NGINXINFO[pid-path]})
	
	if [[ $RUNLEVEL -eq 99 ]]; then printf "%s\n" "${!NGINXINFO[@]}" "${NGINXINFO[@]}" | pr -2t; fi
	if [[ $RUNLEVEL -eq 99 ]]; then printf "%s\n" "${!HOSTINFO[@]}" "${HOSTINFO[@]}" | pr -2t; fi
	
	if [[ $RUNLEVEL -gt 9 ]]; then
	    echo ""
		echo "  NGINX Info Report"
		echo "  ================="
		echo "  - Version: "'`'"$NGINXIFOVERSION"'`'""
		echo "  - Source: https://github.com/tippexs/ngxinfo"
		echo "  - Build date: $(date -d $BUILD +%Y-%m-%d)"
		echo ""
		if [[ $(( ($(date +%s)- $(date -d $BUILD +%s) ) / 86400 )) -gt 89 ]]; then
		  echo "   ${COLYELLOW}** WARNING **${COLRES} The source data for modules, directives, and CVE information is more than 90 days old."
		  echo "                 Please consider rebuilding this script from source."		
		fi
		echo ""
		echo "  NGINX Version"
		echo "  -------------"
		echo ""
		echo "  - NGINX version: $NGXVERSION"
		echo "  - OpenSSL version: $OPENSSLVERSION"
		echo ""
		
		echo "  Configuration"
		echo "  -------------"
		echo ""
		sys::net
		cat /proc/$NGXPID/cmdline &> /dev/null 2>&1
	      if [ $? -ne 0 ]; then
	        echo "${COLYELLOW}  NGINX is installed but not up and running. No network information available.${COLRES}";
	        NGXRUNSTAT=0
	      fi
	fi

	NGXPREF=$(echo ${NGINXINFO[prefix]} |sed 's/^[[:space:]]*//g')

	#is NGINX up and running?
	
	#Kick-Off - Copy NGINX Main Config file to tmp-file
	cat ${NGINXINFO[conf-path]} > config1.tmp
	#grep config-file search for include. if include present
	while [ true ]
	do
	  egrep -i "^\s*include" config1.tmp &> /dev/null 2>&1
	  if [ $? -eq 0 ]
	  then
		ngx::include_test "$(cat config1.tmp)";
	  else
		break;
	  fi
	done
	
	ngx::parse_configuration
	ngx::directives
	[[ $RUNLEVEL == 99 ]] && ngx::directives_verbose
	ngx::directive_check
	ngx::module_check
    if [[ $RUNLEVEL -gt 9 ]]; then
	  echo ""
      echo "  Security"
	  echo "  --------"
	  echo ""
	fi
    ngx::cve

}

main::cleanup() {
  rm -f config.tmp config1.tmp alldirs.txt allmodules.txt module-config.tmp
}
"""

bash_end = r"""
main::preflight
ngx::instance_information
sys::hostinfo

if [ $# -eq 0 ]; then
	RUNLEVEL=10
	main::run
	main::cleanup
	main::exitcode
else 
	while [ $# -ge 1 ]; do
	  case "$1" in
		"-h" | "--help")
		  main::helpscreen
		  shift
		;;
		"-q" | "--quite")
		  RUNLEVEL=1
		  main::run
		  main::cleanup
		  main::exitcode
		  shift
		;;
		"-v" | "--verbose")
		  RUNLEVEL=99
		  main::run
		  main::cleanup
		  main::exitcode
		  shift
		;;
		*)
		  main::helpscreen 9
		  shift
		;;
	  esac
	done
fi
"""

with open('parse.awk', 'r') as pfile:
    parseawk = pfile.read()
    pfile.close()

awk = parseawk.replace('\';','\'"\'"\';')

print (f"#!/usr/bin/env bash\n{bash_vars}\nCVELIST='{s}'\nBUILD='{build}'\n\nALLMODULES='{m}'\n\nALLDIRECTIVES='{de}'\n\n{bash_main_functions}\n")
print(bash_awk,awk,bash_awk_end)
print(f"{bash_end}")