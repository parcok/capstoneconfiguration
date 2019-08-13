BARNYARD_VERSION=2-1.13
DAQ_VERSION=2.0.6
SNORT_VERSION=2.9.13
HOSTNAME=$(hostname)
INTERFACE=$(route -n | awk '$1 == "0.0.0.0" {print $8}')
LOCAL_IP=$(hostname -I | awk '{print $1}')
SID_FILE=~/snort-$SNORT_VERSION/etc/sid-msg.map

# Have to generate the sid-map file and copy it over
cd ~/snort-$SNORT_VERSION/rules
# Generation of the sid-map is a bitch
regex='msg:\s?\"([^"]*?)";.*sid:\s?([[:digit:]]+)\;'
regex2='sid:\s?([[:digit:]]+)\;.*msg:\s?\"([^"]*?)";'
for file in *.rules; do
 [ -f "$file" ] || break
 while IFS='' read -r line || [[ -n "$line" ]]; do
  if [[ "$line" =~ $regex ]]; then
   echo "${BASH_REMATCH[2]}" '||' "${BASH_REMATCH[1]}" >> sid-msg.map
   #mysql --execute="insert into snort.signature (sig_name, sig_class_id, sig_priority, sig_rev, sig_sid, sig_gid) values (\"${BASH_REMATCH[1]}\", 0, 0, 1, ${BASH_REMATCH[2]}, 1);"
  elif [[ "$line" =~ $regex2 ]]; then
   echo "${BASH_REMATCH[1]}" '||' "${BASH_REMATCH[2]}" >> sid-msg.map
   #mysql --execute="insert into snort.signature (sig_name, sig_class_id, sig_priority, sig_rev, sig_sid, sig_gid) values (\"${BASH_REMATCH[2]}\", 0, 0, 1, ${BASH_REMATCH[1]}, 1);"
  fi
 done < $file
done
# Copy the sid-msg.map over to where it needs to go and continue
mv sid-msg.map ../etc/

# Sort rules by SID number because I want to
sort -o ~/snort-$SNORT_VERSION/etc/sid-msg.map ~/snort-$SNORT_VERSION/etc/sid-msg.map

# Generate the gen-msg.map file
cat ~/snort-$SNORT_VERSION/etc/sid-msg.map | awk -F '|' '{print "1 || "$1"||"$3}' > ~/snort-$SNORT_VERSION/etc/gen-msg.map

# Insert the rules into the database now
mysql --execute="truncate snort.signature;"

regex3='^([0-9]+)\s\|\|\s(.*)$';
while IFS='' read -r line || [[ -n "$line" ]]; do
 if [[ "$line" =~ $regex3 ]]; then
  mysql --execute="insert into snort.signature (sig_name, sig_class_id, sig_priority, sig_rev, sig_sid, sig_gid) values (\"${BASH_REMATCH[2]}\", 0, 0, 1, ${BASH_REMATCH[1]}, 1);"
 else
  echo "No match.";
 fi
done < $SID_FILE
echo "Rules inserted into the database.";
