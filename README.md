# Lab2
### Name: Zhanfu Yang 
### Email: yang1676@purdue.edu

## UDP 1
In this section we are going to spoof the user with the fake response.

First in the Server: 
`sudo rndc flush`
`sudo /etc/init.d/bind9 restart`

Then in the Attacker, run the run.sh
`bash ./run.sh`

Then in the server, run the check.sh to check whether there are attacker signal  from the Attacker.
`bash check.sh`

## UDP 2
In this section, bases on the UDP 1, after setting the correct parameter
run : `dig www.example.edu`
