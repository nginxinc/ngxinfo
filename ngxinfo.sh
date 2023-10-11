#!/usr/bin/env bash

## build.py (c) NGINX, Inc. [10/6/2021] Timo Stark <t.stark@f5.com>
## Build script for nginxinfo v0.0.1 alpha

COLGREEN=$(tput setaf 2)
COLYELLOW=$(tput setaf 3)
COLRED=$(tput setaf 1)
COLRES=$(tput sgr0)

NGXV=""
NGINXIFOVERSION="nginxinfo v0.1 alpha"
NGXVERSION=$(nginx -v 2>&1 |grep -Po '[0-9]+(\.[0-9]+)+')
OPENSSLVERSION=$(openssl version)
HOSTINFORMATION=$(cat /etc/os-release | tr '\n' '^' | tr -d '"')
NGXMAINCMD=$(ps -axo pid,cmd | grep '[n]ginx: master process' | awk '{print $5}')
NGXMAINPID=$(ps -axo pid,cmd | grep '[n]ginx: master process' | awk '{print $4}')
WHICHNGX=$(which nginx 2>&1)
NGXRUNSTATE=1
DIRERRORCNT=1
RUNLEVEL=""
EXITCODE=0
FOUND=0;
NFOUND=0;
MNFOUND=0;
CVEFOUND=0;

#HTTP2 CVE
HTTP2_MCE=0;
KEEPAL=0;

CVELIST='2022-41741;1.1.3-1.23.1;1.23.2+,1.22.1+;Memory corruption in the ngx_http_mp4_module;
2022-41741;1.0.7-1.0.15;1.23.2+,1.22.1+;Memory corruption in the ngx_http_mp4_module;
2022-41742;1.1.3-1.23.1;1.23.2+,1.22.1+;Memory disclosure in the ngx_http_mp4_module;
2022-41742;1.0.7-1.0.15;1.23.2+,1.22.1+;Memory disclosure in the ngx_http_mp4_module;
2021-23017;0.6.18-1.20.0;1.21.0+,1.20.1+;1-byte memory overwrite in resolver;
2019-9511;1.9.5-1.17.2;1.17.3+,1.16.1+;Excessive CPU usage in HTTP/2 with small window updates;
2019-9513;1.9.5-1.17.2;1.17.3+,1.16.1+;Excessive CPU usage in HTTP/2 with priority changes;
2019-9516;1.9.5-1.17.2;1.17.3+,1.16.1+;Excessive memory usage in HTTP/2 with zero length headers;
2018-16843;1.9.5-1.15.5;1.15.6+,1.14.1+;Excessive memory usage in HTTP/2;
2018-16844;1.9.5-1.15.5;1.15.6+,1.14.1+;Excessive CPU usage in HTTP/2;
2018-16845;1.1.3-1.15.5;1.15.6+,1.14.1+;Memory disclosure in the ngx_http_mp4_module;
2018-16845;1.0.7-1.0.15;1.15.6+,1.14.1+;Memory disclosure in the ngx_http_mp4_module;
2017-7529;0.5.6-1.13.2;1.13.3+,1.12.1+;Integer overflow in the range filter;
2016-4450;1.3.9-1.11.0;1.11.1+,1.10.1+;NULL pointer dereference while writing client request body;
2016-0742;0.6.18-1.9.9;1.9.10+,1.8.1+;Invalid pointer dereference in resolver;
2016-0746;0.6.18-1.9.9;1.9.10+,1.8.1+;Use-after-free during CNAME response processing in resolver;
2016-0747;0.6.18-1.9.9;1.9.10+,1.8.1+;Insufficient limits of CNAME resolution in resolver;
2014-3616;0.5.6-1.7.4;1.7.5+,1.6.2+;SSL session reuse vulnerability;
2014-3556;1.5.6-1.7.3;1.7.4+,1.6.1+;STARTTLS command injection;
2014-0133;1.3.15-1.5.11;1.5.12+,1.4.7+;SPDY heap buffer overflow;
2014-0088;1.5.10;1.5.11+;SPDY memory corruption;
2013-4547;0.8.41-1.5.6;1.5.7+,1.4.4+;Request line parsing vulnerability;
2013-2070;1.1.4-1.2.8;1.5.0+,1.4.1+,1.2.9+;Memory disclosure with specially crafted HTTP backend responses;
2013-2070;1.3.9-1.4.0;1.5.0+,1.4.1+,1.2.9+;Memory disclosure with specially crafted HTTP backend responses;
2013-2028;1.3.9-1.4.0;1.5.0+,1.4.1+;Stack-based buffer overflow with specially crafted request;
2012-2089;1.1.3-1.1.18;1.1.19+,1.0.15+;Buffer overflow in the ngx_http_mp4_module;
2012-2089;1.0.7-1.0.14;1.1.19+,1.0.15+;Buffer overflow in the ngx_http_mp4_module;
2012-1180;0.1.0-1.1.16;1.1.17+,1.0.14+;Memory disclosure with specially crafted backend responses;
2011-4315;0.6.18-1.1.7;1.1.8+,1.0.10+;Buffer overflow in resolver;
2009-3555;0.1.0-0.8.22;0.8.23+,0.7.64+;The renegotiation vulnerability in SSL protocol;
2009-3898;0.1.0-0.8.16;0.8.17+,0.7.63+;Directory traversal vulnerability;
2009-2629;0.1.0-0.8.14;0.8.15+,0.7.62+,0.6.39+,0.5.38+;Buffer underflow vulnerability;
2009-3896;0.1.0-0.8.13;0.8.14+,0.7.62+,0.6.39+,0.5.38+;Null pointer dereference vulnerability;
'
BUILD='2023-10-11'

ALLMODULES='ngx_http_modsecurity_module.so;
ngx_fips_check_module.so;
ngx_http_js_module.so;
ngx_stream_js_module.so;
ndk_http_module.so;
ngx_http_encrypted_session_module.so;
ngx_http_xslt_filter_module.so;
ngx_http_headers_more_filter_module.so;
ngx_rtmp_module.so;
ngx_http_auth_spnego_module.so;
ngx_http_geoip_module.so;
ngx_stream_geoip_module.so;
ngx_http_brotli_filter_module.so;
ngx_http_brotli_static_module.so;
ngx_http_subs_filter_module.so;
ngx_http_image_filter_module.so;
ngx_otel_module.so;
ngx_http_passenger_module.so;
ndk_http_module.so;
ngx_http_set_misc_module.so;
ngx_http_perl_module.so;
ngx_http_opentracing_module.so;
ndk_http_module.so;
ngx_http_lua_module.so;
ngx_stream_lua_module.so;
ndk_http_module.so;
ngx_http_geoip2_module.so;
ngx_stream_geoip2_module.so;
'

ALLDIRECTIVES='absolute_redirect
accept_mutex
accept_mutex_delay
access_log
add_after_body
add_before_body
add_header
add_trailer
addition_types
aio
aio_write
alias
allow
ancient_browser
ancient_browser_value
api
auth_basic
auth_basic_user_file
auth_delay
auth_http
auth_http_header
auth_http_pass_client_cert
auth_http_timeout
auth_jwt
auth_jwt_claim_set
auth_jwt_header_set
auth_jwt_key_cache
auth_jwt_key_file
auth_jwt_key_request
auth_jwt_leeway
auth_jwt_require
auth_jwt_type
auth_request
auth_request_set
autoindex
autoindex_exact_size
autoindex_format
autoindex_localtime
break
charset
charset_map
charset_types
chunked_transfer_encoding
client_body_buffer_size
client_body_in_file_only
client_body_in_single_buffer
client_body_temp_path
client_body_timeout
client_header_buffer_size
client_header_timeout
client_max_body_size
connection_pool_size
create_full_put_path
daemon
dav_access
dav_methods
debug_connection
debug_points
default_type
deny
directio
directio_alignment
disable_symlinks
empty_gif
env
error_log
error_page
etag
events
expires
f4f
f4f_buffer_size
fastcgi_bind
fastcgi_buffer_size
fastcgi_buffering
fastcgi_buffers
fastcgi_busy_buffers_size
fastcgi_cache
fastcgi_cache_background_update
fastcgi_cache_bypass
fastcgi_cache_key
fastcgi_cache_lock
fastcgi_cache_lock_age
fastcgi_cache_lock_timeout
fastcgi_cache_max_range_offset
fastcgi_cache_methods
fastcgi_cache_min_uses
fastcgi_cache_path
fastcgi_cache_purge
fastcgi_cache_revalidate
fastcgi_cache_use_stale
fastcgi_cache_valid
fastcgi_catch_stderr
fastcgi_connect_timeout
fastcgi_force_ranges
fastcgi_hide_header
fastcgi_ignore_client_abort
fastcgi_ignore_headers
fastcgi_index
fastcgi_intercept_errors
fastcgi_keep_conn
fastcgi_limit_rate
fastcgi_max_temp_file_size
fastcgi_next_upstream
fastcgi_next_upstream_timeout
fastcgi_next_upstream_tries
fastcgi_no_cache
fastcgi_param
fastcgi_pass
fastcgi_pass_header
fastcgi_pass_request_body
fastcgi_pass_request_headers
fastcgi_read_timeout
fastcgi_request_buffering
fastcgi_send_lowat
fastcgi_send_timeout
fastcgi_socket_keepalive
fastcgi_split_path_info
fastcgi_store
fastcgi_store_access
fastcgi_temp_file_write_size
fastcgi_temp_path
flv
geo
geoip_city
geoip_country
geoip_org
geoip_proxy
geoip_proxy_recursive
google_perftools_profiles
grpc_bind
grpc_buffer_size
grpc_connect_timeout
grpc_hide_header
grpc_ignore_headers
grpc_intercept_errors
grpc_next_upstream
grpc_next_upstream_timeout
grpc_next_upstream_tries
grpc_pass
grpc_pass_header
grpc_read_timeout
grpc_send_timeout
grpc_set_header
grpc_socket_keepalive
grpc_ssl_certificate
grpc_ssl_certificate_key
grpc_ssl_ciphers
grpc_ssl_conf_command
grpc_ssl_crl
grpc_ssl_name
grpc_ssl_password_file
grpc_ssl_protocols
grpc_ssl_server_name
grpc_ssl_session_reuse
grpc_ssl_trusted_certificate
grpc_ssl_verify
grpc_ssl_verify_depth
gunzip
gunzip_buffers
gzip
gzip_buffers
gzip_comp_level
gzip_disable
gzip_http_version
gzip_min_length
gzip_proxied
gzip_static
gzip_types
gzip_vary
hash
health_check
health_check_timeout
hls
hls_buffers
hls_forward_args
hls_fragment
hls_mp4_buffer_size
hls_mp4_max_buffer_size
http
http2
http2_body_preread_size
http2_chunk_size
http2_idle_timeout
http2_max_concurrent_pushes
http2_max_concurrent_streams
http2_max_field_size
http2_max_header_size
http2_max_requests
http2_push
http2_push_preload
http2_recv_buffer_size
http2_recv_timeout
http3
http3_hq
http3_max_concurrent_streams
http3_stream_buffer_size
if
if_modified_since
ignore_invalid_headers
image_filter
image_filter_buffer
image_filter_interlace
image_filter_jpeg_quality
image_filter_sharpen
image_filter_transparency
image_filter_webp_quality
imap_auth
imap_capabilities
imap_client_buffer
include
index
internal
internal_redirect
ip_hash
js_access
js_body_filter
js_content
js_fetch_buffer_size
js_fetch_ciphers
js_fetch_max_response_buffer_size
js_fetch_protocols
js_fetch_timeout
js_fetch_trusted_certificate
js_fetch_verify
js_fetch_verify_depth
js_filter
js_header_filter
js_import
js_include
js_path
js_periodic
js_preload_object
js_preread
js_set
js_shared_dict_zone
js_var
keepalive
keepalive_disable
keepalive_requests
keepalive_time
keepalive_timeout
keyval
keyval_zone
large_client_header_buffers
least_conn
least_time
limit_conn
limit_conn_dry_run
limit_conn_log_level
limit_conn_status
limit_conn_zone
limit_except
limit_rate
limit_rate_after
limit_req
limit_req_dry_run
limit_req_log_level
limit_req_status
limit_req_zone
limit_zone
lingering_close
lingering_time
lingering_timeout
listen
load_module
location
lock_file
log_format
log_not_found
log_subrequest
mail
map
map_hash_bucket_size
map_hash_max_size
master_process
match
max_errors
max_ranges
memcached_bind
memcached_buffer_size
memcached_connect_timeout
memcached_gzip_flag
memcached_next_upstream
memcached_next_upstream_timeout
memcached_next_upstream_tries
memcached_pass
memcached_read_timeout
memcached_send_timeout
memcached_socket_keepalive
merge_slashes
min_delete_depth
mirror
mirror_request_body
modern_browser
modern_browser_value
mp4
mp4_buffer_size
mp4_limit_rate
mp4_limit_rate_after
mp4_max_buffer_size
mp4_start_key_frame
mqtt
mqtt_buffers
mqtt_preread
mqtt_rewrite_buffer_size
mqtt_set_connect
msie_padding
msie_refresh
multi_accept
ntlm
open_file_cache
open_file_cache_errors
open_file_cache_min_uses
open_file_cache_valid
open_log_file_cache
otel_exporter
otel_service_name
otel_span_attr
otel_span_name
otel_trace
otel_trace_context
output_buffers
override_charset
pcre_jit
perl
perl_modules
perl_require
perl_set
pid
pop3_auth
pop3_capabilities
port_in_redirect
postpone_output
preread_buffer_size
preread_timeout
protocol
proxy_bind
proxy_buffer
proxy_buffer_size
proxy_buffering
proxy_buffers
proxy_busy_buffers_size
proxy_cache
proxy_cache_background_update
proxy_cache_bypass
proxy_cache_convert_head
proxy_cache_key
proxy_cache_lock
proxy_cache_lock_age
proxy_cache_lock_timeout
proxy_cache_max_range_offset
proxy_cache_methods
proxy_cache_min_uses
proxy_cache_path
proxy_cache_purge
proxy_cache_revalidate
proxy_cache_use_stale
proxy_cache_valid
proxy_connect_timeout
proxy_cookie_domain
proxy_cookie_flags
proxy_cookie_path
proxy_download_rate
proxy_force_ranges
proxy_half_close
proxy_headers_hash_bucket_size
proxy_headers_hash_max_size
proxy_hide_header
proxy_http_version
proxy_ignore_client_abort
proxy_ignore_headers
proxy_intercept_errors
proxy_limit_rate
proxy_max_temp_file_size
proxy_method
proxy_next_upstream
proxy_next_upstream_timeout
proxy_next_upstream_tries
proxy_no_cache
proxy_pass
proxy_pass_error_message
proxy_pass_header
proxy_pass_request_body
proxy_pass_request_headers
proxy_protocol
proxy_protocol_timeout
proxy_read_timeout
proxy_redirect
proxy_request_buffering
proxy_requests
proxy_responses
proxy_send_lowat
proxy_send_timeout
proxy_session_drop
proxy_set_body
proxy_set_header
proxy_smtp_auth
proxy_socket_keepalive
proxy_ssl
proxy_ssl_certificate
proxy_ssl_certificate_key
proxy_ssl_ciphers
proxy_ssl_conf_command
proxy_ssl_crl
proxy_ssl_name
proxy_ssl_password_file
proxy_ssl_protocols
proxy_ssl_server_name
proxy_ssl_session_reuse
proxy_ssl_trusted_certificate
proxy_ssl_verify
proxy_ssl_verify_depth
proxy_store
proxy_store_access
proxy_temp_file_write_size
proxy_temp_path
proxy_timeout
proxy_upload_rate
queue
quic_active_connection_id_limit
quic_bpf
quic_gso
quic_host_key
quic_retry
random
random_index
read_ahead
real_ip_header
real_ip_recursive
recursive_error_pages
referer_hash_bucket_size
referer_hash_max_size
request_pool_size
reset_timedout_connection
resolver
resolver_timeout
return
rewrite
rewrite_log
root
satisfy
scgi_bind
scgi_buffer_size
scgi_buffering
scgi_buffers
scgi_busy_buffers_size
scgi_cache
scgi_cache_background_update
scgi_cache_bypass
scgi_cache_key
scgi_cache_lock
scgi_cache_lock_age
scgi_cache_lock_timeout
scgi_cache_max_range_offset
scgi_cache_methods
scgi_cache_min_uses
scgi_cache_path
scgi_cache_purge
scgi_cache_revalidate
scgi_cache_use_stale
scgi_cache_valid
scgi_connect_timeout
scgi_force_ranges
scgi_hide_header
scgi_ignore_client_abort
scgi_ignore_headers
scgi_intercept_errors
scgi_limit_rate
scgi_max_temp_file_size
scgi_next_upstream
scgi_next_upstream_timeout
scgi_next_upstream_tries
scgi_no_cache
scgi_param
scgi_pass
scgi_pass_header
scgi_pass_request_body
scgi_pass_request_headers
scgi_read_timeout
scgi_request_buffering
scgi_send_timeout
scgi_socket_keepalive
scgi_store
scgi_store_access
scgi_temp_file_write_size
scgi_temp_path
secure_link
secure_link_md5
secure_link_secret
send_lowat
send_timeout
sendfile
sendfile_max_chunk
server
server_name
server_name_in_redirect
server_names_hash_bucket_size
server_names_hash_max_size
server_tokens
session_log
session_log_format
session_log_zone
set
set_real_ip_from
slice
smtp_auth
smtp_capabilities
smtp_client_buffer
smtp_greeting_delay
source_charset
split_clients
ssi
ssi_last_modified
ssi_min_file_chunk
ssi_silent_errors
ssi_types
ssi_value_length
ssl
ssl_alpn
ssl_buffer_size
ssl_certificate
ssl_certificate_key
ssl_ciphers
ssl_client_certificate
ssl_conf_command
ssl_crl
ssl_dhparam
ssl_early_data
ssl_ecdh_curve
ssl_engine
ssl_handshake_timeout
ssl_ocsp
ssl_ocsp_cache
ssl_ocsp_responder
ssl_password_file
ssl_prefer_server_ciphers
ssl_preread
ssl_protocols
ssl_reject_handshake
ssl_session_cache
ssl_session_ticket_key
ssl_session_tickets
ssl_session_timeout
ssl_stapling
ssl_stapling_file
ssl_stapling_responder
ssl_stapling_verify
ssl_trusted_certificate
ssl_verify_client
ssl_verify_depth
starttls
state
status
status_format
status_zone
sticky
sticky_cookie_insert
stream
stub_status
sub_filter
sub_filter_last_modified
sub_filter_once
sub_filter_types
subrequest_output_buffer_size
tcp_nodelay
tcp_nopush
thread_pool
timeout
timer_resolution
try_files
types
types_hash_bucket_size
types_hash_max_size
underscores_in_headers
uninitialized_variable_warn
upstream
upstream_conf
use
user
userid
userid_domain
userid_expires
userid_flags
userid_mark
userid_name
userid_p3p
userid_path
userid_service
uwsgi_bind
uwsgi_buffer_size
uwsgi_buffering
uwsgi_buffers
uwsgi_busy_buffers_size
uwsgi_cache
uwsgi_cache_background_update
uwsgi_cache_bypass
uwsgi_cache_key
uwsgi_cache_lock
uwsgi_cache_lock_age
uwsgi_cache_lock_timeout
uwsgi_cache_max_range_offset
uwsgi_cache_methods
uwsgi_cache_min_uses
uwsgi_cache_path
uwsgi_cache_purge
uwsgi_cache_revalidate
uwsgi_cache_use_stale
uwsgi_cache_valid
uwsgi_connect_timeout
uwsgi_force_ranges
uwsgi_hide_header
uwsgi_ignore_client_abort
uwsgi_ignore_headers
uwsgi_intercept_errors
uwsgi_limit_rate
uwsgi_max_temp_file_size
uwsgi_modifier1
uwsgi_modifier2
uwsgi_next_upstream
uwsgi_next_upstream_timeout
uwsgi_next_upstream_tries
uwsgi_no_cache
uwsgi_param
uwsgi_pass
uwsgi_pass_header
uwsgi_pass_request_body
uwsgi_pass_request_headers
uwsgi_read_timeout
uwsgi_request_buffering
uwsgi_send_timeout
uwsgi_socket_keepalive
uwsgi_ssl_certificate
uwsgi_ssl_certificate_key
uwsgi_ssl_ciphers
uwsgi_ssl_conf_command
uwsgi_ssl_crl
uwsgi_ssl_name
uwsgi_ssl_password_file
uwsgi_ssl_protocols
uwsgi_ssl_server_name
uwsgi_ssl_session_reuse
uwsgi_ssl_trusted_certificate
uwsgi_ssl_verify
uwsgi_ssl_verify_depth
uwsgi_store
uwsgi_store_access
uwsgi_temp_file_write_size
uwsgi_temp_path
valid_referers
variables_hash_bucket_size
variables_hash_max_size
worker_aio_requests
worker_connections
worker_cpu_affinity
worker_priority
worker_processes
worker_rlimit_core
worker_rlimit_nofile
worker_shutdown_timeout
working_directory
xclient
xml_entities
xslt_last_modified
xslt_param
xslt_string_param
xslt_stylesheet
xslt_types
zone
zone_sync
zone_sync_buffers
zone_sync_connect_retry_interval
zone_sync_connect_timeout
zone_sync_interval
zone_sync_recv_buffer_size
zone_sync_server
zone_sync_ssl
zone_sync_ssl_certificate
zone_sync_ssl_certificate_key
zone_sync_ssl_ciphers
zone_sync_ssl_conf_command
zone_sync_ssl_crl
zone_sync_ssl_name
zone_sync_ssl_password_file
zone_sync_ssl_protocols
zone_sync_ssl_server_name
zone_sync_ssl_trusted_certificate
zone_sync_ssl_verify
zone_sync_ssl_verify_depth
zone_sync_timeout'


declare -A NGINXINFO
declare -A HOSTINFO
declare -A CONFIGURATION
declare -A CVES

main::preflight() {
	if [[ $(ps -ax | grep '[n]ginx: master process' | wc -l) -gt 1 ]]; then
	  echo "${COLRED} Multiple NGINX master processes detected. Looks like you are running multiple instances?! ERROR ${COLRES}";
	  exit 99	
	fi

	if [ "$WHICHNGX" != "/usr/sbin/nginx" ] && [ "$WHICHNGX" != "/usr/local/sbin/nginx" ]; then
	  echo "${COLYELLOW} NGINX binary found in non-standard Path or not found! ${COLRES}";
	fi
	
	if [ $NGXMAINCMD ]; then 
		NGXBINARY=$NGXMAINCMD
		NGXV=$($NGXMAINCMD -V 2>&1)
	else
		echo "${COLYELLOW}  NGINX not running. Using binary from system path. ${COLRES}";
		NGXBINARY=$WHICHNGX
		NGXV=$($WHICHNGX -V 2>&1)
	fi
}


ngx::provenance() {
	NGXREPO=$(find /etc/yum* /etc/apt /etc/apk -type f -exec grep -H nginx\.com/packages/ {} \; 2>&1 | grep -c ^/)
	NGXPCKVENDOR="N.A."
	if [ $NGXREPO -gt 0 ]; then
		NGXPCKVENDOR="NGINX Inc."
	else
		case "${HOSTINFO[ID]}" in
			"centos" | "rhel" | "fedora")
			NGXPCKVENDOR=$(rpm -q --info nginx | grep Vendor | awk '{print $NF}')
			;;
			"ubuntu" | "debian")
			NGXPCKVENDOR=$(apt show nginx 2> /dev/null | grep Origin: | awk '{print $NF}')
			;;
			*)
			NGXPCKVENDOR="OS-Package not found!"
			;;
		esac
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
		  ngx::ngx_config_writer $configinc "/tmp/config1.tmp"
        else
		  ngx::ngx_config_writer "${NGINXINFO[conf-path]%/*}/$configinc" "/tmp/config1.tmp"
		fi
	else
		echo "$1" >> /tmp/config1.tmp
	fi
}

ngx::include_test() {
	rm /tmp/config1.tmp;
	while IFS= read -r line ; do ngx::finder "$line"; done <<< "$1"
}

ngx::directives() {
  for i in `cat /tmp/config.tmp | tr -d '\t\n{}' | tr ';' '\n' | grep -v '#' | awk '{print $1}'`; do
       if [[ $i != *['!'*@#\$%^\&*()+\=\"]* ]]; then
       #@todo: Check for CVE2023-44487
       #Check if keepalive_requests, http2_max_concurrent_streams
       if [[ $i == 'keepalive_requests' ]]; then
         KEEPAL=1
	 CVEFOUND=1
       fi
       if [[ $i == 'http2_max_concurrent_streams' ]]; then
         HTTP2_MCE=1
	 CVEFOUND=1
       fi
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
		 CVETEXT=$(echo $line |awk '{ split($0,a,";"); print a[4] }')

		 if [ `echo $VULNERABLE"-"$NGXVERSION | tr '-' '\n' | sort -Vr | head -1` != $NGXVERSION ]; then
		   if [ `echo $VULNERABLE"-"$NGXVERSION | tr '-' '\n' | sort -V | head -1` == $NGXVERSION ]; then
			  continue
		   fi
           SKIP=0
		   #checking the good values
		   MESSAGE="CVE $CVE, $CVETEXT"
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
	
	if [[ $CVEFOUND -eq 0 ]] && [[ $RUNLEVEL -gt 9 ]]; then echo "${COLGREEN}  - This configuration is not affected by any known vulnerabilities.${COLRES}"; fi
}

ngx::module_check() {
  if [ -f "/tmp//module-config.tmp" ]; then
	echo "$ALLMODULES" > /tmp/allmodules.txt
	while read m; do
	if grep -Fqx "${m##*/}" /tmp/allmodules.txt; then
		   [[ $RUNLEVEL == 99 ]] && echo ${COLGREEN}"Found $m"${COLRES}
		   ((++FOUND))
		else
		   if [[ $MNFOUND -eq 0 ]] && [[ $RUNLEVEL -gt 9 ]]; then echo "  - Found unsupoported modules: "; fi
		     [[ $RUNLEVEL -gt 9 ]] && echo ${COLRED}"    - ${m##*/}"${COLRES}
		     ((++MNFOUND))
		fi
	done < /tmp/module-config.tmp | tr -d '"' | tr -d "'" | tr -d ";"
  fi  
}

ngx::directive_check() {
	 echo -e "$ALLDIRECTIVES" > /tmp/alldirs.txt
	 for x in "${!CONFIGURATION[@]}"; do
		if grep -Fxq "$x" /tmp/alldirs.txt; then
			[[ $RUNLEVEL == 99 ]] && echo ${COLGREEN}"Found $x ${CONFIGURATION[$x]}x${COLRES}" ;((++FOUND))
		else
			if [[ $NFOUND -eq 0 ]] && [[ $RUNLEVEL -gt 9 ]]; then echo "  - Found unsupoported directives: "; fi
			[[ $RUNLEVEL -gt 9 ]] && echo ${COLRED}"    - $x (x${CONFIGURATION[$x]})${COLRES}" ;((++NFOUND))
		fi
	done
    if [[ $RUNLEVEL -gt 9 ]] && [[ $NFOUND -eq 0 ]]; then echo "${COLGREEN}  No unknown directives found. ${COLRES}"; fi
}

main::exitcode() {
# 0 = OK
# 1 = WARNING
# 2 = ERRORS
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
 	  EXITCODE=1
 	fi
 	
    if [[ $NFOUND -gt 0 ]] || [[ $MNFOUND -gt 0 ]]; then
 	 
 	  EXITCODE=2
 	fi	
  else
 	EXITCODE=2
  fi

  case $EXITCODE in
    0)
     if [[ $RUNLEVEL -gt 9 ]]; then echo "${COLGREEN}  Congratulations! No warnings or errors found! You are good upgrading to NGINX Plus.${COLRES}"; fi
     ;;
   1)
     if [[ $CVEFOUND -ne 0 ]] && [[ $RUNLEVEL -gt 9 ]]; then echo "${COLYELLOW}   * It is recommended to upgrade to a more recent version of NGINX to address the known security vulnerabilities.${COLRES}"; fi
     if [[ $RUNLEVEL -gt 9 ]]; then echo "${COLYELLOW}   * There are warnings but you are good upgrading to NGINX Plus. Congratulations!${COLRES}"; fi
   ;;
   2)
    if [[ $RUNLEVEL -gt 9 ]]; then echo "${COLRED} * Do not upgrade${COLRES} to NGINX Plus without first discussing this project with your F5/NGINX representative"; fi
   ;;
   *)
    if [[ $RUNLEVEL -gt 9 ]]; then echo "${COLRED} * An error ocurred! ${COLRES} Please contact your F5/NGINX representative"; fi
   ;;
  esac

 exit $EXITCODE
}

main::run() {
	if [[ $RUNLEVEL -eq 99 ]]; then printf "%s\n" "${!NGINXINFO[@]}" "${NGINXINFO[@]}" | pr -2t; fi
	if [[ $RUNLEVEL -eq 99 ]]; then printf "%s\n" "${!HOSTINFO[@]}" "${HOSTINFO[@]}" | pr -2t; fi
	
	if [[ $RUNLEVEL -gt 9 ]]; then
	    echo ""
		echo "  NGINX Info Report"
		echo "  ================="
		echo "  - Version: "'`'"$NGINXIFOVERSION"'`'""
		echo "  - Binary:  "'`'"$NGXBINARY"'`'""
		echo "  - Source: https://github.com/nginxinc/ngxinfo"
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
		ngx::provenance
		echo "  - Provenance: $NGXPCKVENDOR"
		echo ""
		echo "  Configuration"
		echo "  -------------"
		echo ""
	fi

	NGXPREF=$(echo ${NGINXINFO[prefix]} |sed 's/^[[:space:]]*//g')

	#is NGINX up and running?
	
	#Kick-Off - Copy NGINX Main Config file to tmp-file
	cat ${NGINXINFO[conf-path]} > /tmp/config1.tmp
	#grep config-file search for include. if include present
	while [ true ]
	do
	  egrep -i "^\s*include" /tmp/config1.tmp &> /dev/null 2>&1
	  if [ $? -eq 0 ]
	  then
		ngx::include_test "$(cat /tmp/config1.tmp)";
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

    #HTTP2 CVE Update
    if [[  $HTTP2_MCE == 1 ]]; then
      http2_msv=`nginx -T 2>&1 | grep http2_max_concurrent_streams | awk '{print $2}' |sed 's/.$//'`
      for d in $http2_msv; do
      if [[  $d -gt 128 ]]; then
	echo "${COLRED}   !! CVE-2023-44487 !!"
        echo "${COLRED}   We have detected NGINX is configured using http2_max_concurrent_streams. Value: $d";
        echo "${COLRED}   Please see the security advisory at https://nginx.com/blog/"
        echo "${COLRES}"
      fi
      done
     fi
    
    
    if [[ $KEEPAL == 1 ]]; then
       keepal_msv=`nginx -T 2>&1 |grep keepalive_requests | awk '{print $2}' |sed 's/.$//'`
       for d in $keepal_msv; do
       if [[ $d -gt 1000 ]]; then
	echo "${COLRED}   !! CVE-2023-44487 !!"
        echo "${COLRED}   We have detected NGINX is configured using keepalive_requests. Value: $d";
        echo "${COLRED}   Please see the security advisory at https://nginx.com/blog/"
        echo "${COLRES}"
       fi
       done 
    fi	    

}

main::cleanup() {
  rm -f /tmp/config.tmp /tmp/config1.tmp /tmp/alldirs.txt /tmp/allmodules.txt /tmp/module-config.tmp
  rm -rf /tmp/modules/
}



ngx::parse_configuration() {
	FUNCTION='
 {
if (match($0,/^(\s+#|#)(.*)/) != 0) {
   print "Line-Comment skipping..."$0;
   next
}

ose = substr($0, length($0))

if (ose == ";") {
   os = $0
   if (gsub(";", "::", os) != 1) {
     $0 = os ";"
   }
}

if (ose != ";") {
  str = substr($0, index($0, ";")+1)
  if (match(str,/^(\s+#|#)(.*)/) != 0) {
      $0 = substr($0, 0, index($0, ";"))
  }
}

#Edgecase Handline... 
if ($0 ~ /map[a-zA-Z0-9 $ {](.*)(})/) {
  print "Warning: One-liner detected! " $1 $2 $3 "CleanUp needed!";
  next
}
if ($0 ~ /upstream[a-zA-Z0-9 $ {](.*)(})/) {
  print "Warning: One-liner detected! " $1 $2 "CleanUp needed!";
  next
}

#Edgecase Handline END
if (substr($NF, length($2)-1, 1) == ";" ) {
  print $NF"++"$2;
  print "*** Ending Character is ;";
  next
}

if (logblock == 1 ) {
  if (substr($NF, length($NF)-1, 2) == "'"'"';" ) {
    print "EOF Logformat" $0;
    logblock = 0;
    next;
  } else {
      print "still logging..." $0;
      next;
  }
}


if ($1 == "load_module") {
  print $2 > "/tmp/module-config.tmp"
}

if ($1 == "log_format") {
    # check on-line log format.
    if (substr($0, length($0), 1) == ";" ) {
        print "Logformat?? good! One-Liner! Processing as usual" $0;
    }
    else {
      print "Logformat?? good!" $0 "----" substr($0, length($0), 1);
      print $0 > "/tmp/config.tmp"
      logblock = 1;
      next
    } 
}
#parsing a list
#Check upstreams again (removed upstream)
if ($1 == "map" || $1 == "types" || $1 == "content_by_lua_block" ||  $1 == "return" || $1 == "split_clients" || $1 == "match" || $1 == "geo" ) {
    print $0 > "/tmp/config.tmp"
    print "Its a config-block --> " $0;
    mapopen = 1;
    print "OpenConfigBlock is now  " mapopen;
}
else {
    if ($1 == "}" && mapopen == 1) {
        print "Closing config-block";
        mapopen = 0;
    } else {
         if (mapopen == 1) {
             print "InBlockRow: " $0;
         } else {
                  print "Regular NGINX config: " $0;
                  print $0 > "/tmp/config.tmp"
         }
    }
  } 
} 
'
   [[ $RUNLEVEL == 99 ]] && awk "$FUNCTION" /tmp/config1.tmp || awk "$FUNCTION" /tmp/config1.tmp > /dev/null 2>&1
}


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


