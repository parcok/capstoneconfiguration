#!/bin/bash
#Purpose - Create Snort & MySQL setup using Barnyard2
#Created April 23rd 2019
#Last Modified May 31st 2019
#Author - Kevin Parco
#Version 1.4
#START

#barnyard2-2-1.13
#daq-2.0.6
#snort-2.9.13
BARNYARD_VERSION=2-1.13
DAQ_VERSION=2.0.6
SNORT_VERSION=2.9.13
HOSTNAME=$(hostname)
INTERFACE=$(route -n | awk '$1 == "0.0.0.0" {print $8}')
LOCAL_IP=$(hostname -I | awk '{print $1}')
GATEWAY=$(ip route | grep default | cut -d " " -f 3)
NETWORK=$(ip route | sed -n 2p | cut -d " " -f 1)

apt-get upgrade -y
apt-get update -y
apt-get install software-properties-common

# Start of installing MariaDB, which is a MySQL fork
sudo apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 0xF1656F24C74CD1D8
sudo add-apt-repository "deb [arch=amd64,arm64,ppc64el] http://mariadb.mirror.liquidtelecom.com/repo/10.4/ubuntu $(lsb_release -cs) main"
echo "deb http://mirrors.kernel.org/ubuntu bionic main universe" >> /etc/apt/sources.list
apt upgrade -y
apt-get update -y
apt-get install -y mariadb-server mariadb-client libmysqlclient-dev

# Snort pre-requisites
apt-get install -y ethtool build-essential libpcap-dev libpcre3-dev libdumbnet-dev bison flex zlib1g-dev liblzma-dev openssl libssl-dev
apt-get install -y pkg-config libluajit-5.1-2 libluajit-5.1-common libluajit-5.1-dev luajit
apt-get install -y libtool autoconf autogen unzip

# DAQ Installation
wget https://www.snort.org/downloads/snort/daq-$DAQ_VERSION.tar.gz -O daq-$DAQ_VERSION.tar.gz
tar -zxvf daq-$DAQ_VERSION.tar.gz
cd daq-$DAQ_VERSION
./configure && make && make install
cd ~

# Snort Installation
wget https://www.snort.org/downloads/snort/snort-$SNORT_VERSION.tar.gz -O ~/snort-$SNORT_VERSION.tar.gz
tar -xvzf ~/snort-$SNORT_VERSION.tar.gz
cd snort-$SNORT_VERSION
./configure --with-mysql --enable-sourcefire && make && make install
ldconfig
ln -s /usr/local/bin/snort /usr/sbin/snort
cd ~

# Install dnet from source
sudo apt install checkinstall && \
cd /tmp && \
git clone https://github.com/jncornett/libdnet.git && \
cd libdnet && \
sudo -- sh -c './configure;make;make install' && \
sudo make clean && \
sudo cp -R /tmp/libdnet/include/dnet ~/barnyard2-$BARNYARD_VERSION/ && \
sudo make install

# Barnyard & Database

# firnsy version
#wget https://github.com/firnsy/barnyard2/archive/v$BARNYARD_VERSION.tar.gz -O barnyard2-$BARNYARD_VERSION.tar.gz
#tar -zxvf barnyard2-$BARNYARD_VERSION.tar.gz

# parcok version
wget https://codeload.github.com/parcok/barnyard2/zip/master -O barnyard2-$BARNYARD_VERSION.zip
unzip barnyard2-$BARNYARD_VERSION

# 0xjolteon version
#wget https://codeload.github.com/0xjolteon/barnyard2/zip/master -O barnyard2-$BARNYARD_VERSION.zip
#unzip barnyard2-$BARNYARD_VERSION

mv barnyard2-master barnyard2-$BARNYARD_VERSION
cd barnyard2-$BARNYARD_VERSION/schemas
echo "CREATE DATABASE snort;" | mysql -u root
# The forked script should work since it has the backticks in it
# wget https://raw.githubusercontent.com/firnsy/barnyard2/master/schemas/create_mysql -O create_mysql
mysql -D snort -u root < create_mysql
mysql -u root --execute="create user 'snort'@'localhost' identified by 'SuperSecretPassword'; grant create, insert, select, delete, update on snort.* to 'snort'@'localhost';"
cd ../
./autogen.sh
./configure -with-mysql -with-mysql-libraries=/usr/lib/x86_64-linux-gnu
make
make install
cp etc/barnyard2.conf ~/snort-$SNORT_VERSION/etc
# Create folders since they don't run to create it
cd ~/snort-$SNORT_VERSION/etc
mkdir /var/log/barnyard2
mkdir /var/log/snort
chmod 666 /var/log/barnyard2
chmod 666 /var/log/snort
touch /var/log/snort/barnyard2.waldo
# Edit the Barnyard2 configuration a ton
sed -i -e "s/\/etc\/snort\///g" barnyard2.conf
sed -i -e "s/#config logdir: \/tmp/config logdir: \/var\/log\/barnyard2/g" barnyard2.conf
sed -i -e "s/#config hostname:   thor/config hostname: $HOSTNAME/g" barnyard2.conf
sed -i -e "s/#config interface:  eth0/config interface: $INTERFACE/g" barnyard2.conf
sed -i -e "s/#config waldo_file: \/tmp\/waldo/config waldo_file: \/var\/log\/snort\/barnyard2.waldo/g" barnyard2.conf
sed -i -e "s/output alert_fast: stdout/#output alert_fast: stdout/g" barnyard2.conf
sed -i -e "s/#   output database: log, mysql, user=root password=test dbname=db host=localhost/"\
"output database: log, mysql, user=snort password=SuperSecretPassword dbname=snort host=localhost "\
"disable_signature_reference_table/g" barnyard2.conf
# These ones need to be root instead of ~ for some reason
sed -i -e "s/config reference_file:      reference.config/"\
"config reference_file: \/root\/snort-$SNORT_VERSION\/etc\/reference.config/g" barnyard2.conf
sed -i -e "s/config classification_file: classification.config/"\
"config classification_file: \/root\/snort-$SNORT_VERSION\/etc\/classification.config/g" barnyard2.conf
sed -i -e "s/config gen_file:            gen-msg.map/"\
"config gen_file: \/root\/snort-$SNORT_VERSION\/etc\/gen-msg.map/g" barnyard2.conf
sed -i -e "s/config sid_file:            sid-msg.map/"\
"config sid_file: \/root\/snort-$SNORT_VERSION\/etc\/sid-msg.map/g" barnyard2.conf
# Download the rules that are on GitHub
wget https://raw.githubusercontent.com/parcok/capstoneconfiguration/master/rules.zip -O rules.zip
unzip rules.zip -d ~/snort-$SNORT_VERSION
# Have to generate the sid-map file and copy it over
cd ~/snort-$SNORT_VERSION/rules
# Generation of the sid-map is a pain
regex='msg:\"([^"]*?)";.*sid:([[:digit:]]+)\;'
regex2='sid:([[:digit:]]+)\;.*msg:\"([^"]*?)";'
for file in *.rules; do
 [ -f "$file" ] || break
 while IFS='' read -r line || [[ -n "$line" ]]; do
  if [[ "$line" =~ $regex ]]; then
   echo "${BASH_REMATCH[2]}" '||' "${BASH_REMATCH[1]}" >> sid-msg.map
  elif [[ "$line" =~ $regex2 ]]; then
   echo "${BASH_REMATCH[1]}" '||' "${BASH_REMATCH[2]}" >> sid-msg.map
  fi
 done < $file
done
# Copy the sid-msg.map over to where it needs to go and continue
mv sid-msg.map ../etc/
# Sort rules alphabetically because I want to
sort -o ../etc/sid-msg.map ../etc/sid-msg.map

# For now download the config that I made before....
cd ../etc
wget https://raw.githubusercontent.com/parcok/capstoneconfiguration/master/snort.conf -O snort.conf

# Lastly, fix the Snort.conf, this will most likely get changed
cd ~/snort-$SNORT_VERSION/etc
sed -i -e "s/ipvar HOME_NET any/ipvar HOME_NET $LOCAL_IP/g" snort.conf
sed -i -e 's/ipvar EXTERNAL_NET any/ipvar EXTERNAL_NET !$HOME_NET/g' snort.conf
