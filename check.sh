sudo rndc dumpdb -cache
cat /var/cache/bind/dump.db | grep "attacker" | head
