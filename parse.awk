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
  if (substr($NF, length($NF)-1, 2) == "';" ) {
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