set -x
cd /config/datacenter
rmdir nw/pm/vm
rmdir nw/pm
rmdir nw
cd ../routers
rmdir r1
cd ../tanents
rmdir ta
cd /home/lihuiba/macencap/
rmmod config
insmod config.ko
cd /config/
mkdir -p datacenter/nw/pm/vm
mkdir -p routers/r1
mkdir -p tanents/ta
cd tanents/ta
set +x
