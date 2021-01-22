#!/bin/bash
source ../utils.sh

# Contiki directory
CONTIKI=$1
# Test basename
BASENAME=06-oscore-interops-test

IPADDR=fd00::302:304:506:708

# Starting Contiki-NG native node
make -C $CONTIKI/examples/oscore clean >/dev/null
make -C $CONTIKI/examples/oscore > make.log 2> make.err
sleep 10

echo "Downloading leshan"
CALIFORNIUM_JAR=californium-oscore-interops-server.jar
#wget -nc https://joakimeriksson.github.io/resources/$LESHAN_JAR

#Do not run tests 5 through 7, Observe is not implemented yet.
#Skip test 2 since it uses a different context.
#Test 12 seems californium can't pair response without token with request
#Test 16 on Coap-server
for i in {0..1} {3..4} {8..11} {12..15} 17
do
    #echo "Starting native node - oscore server"
    sudo $CONTIKI/examples/oscore/oscore-plugtest-server.native > node.log 2> node.err &
    CPID=$!

    #echo "Starting leshan server"
    java -jar $CALIFORNIUM_JAR $i >californium.log 2>californium.err &
    CALID=$!
    sleep 5
    if grep -q 'TEST OK' californium.log ; then
    	echo "Test $i OK"
    else
  	echo "Test $i FAIL!"
    	
	echo "Closing Californium"
    	sleep 1
    	kill_bg $CALID
	
	echo "Closing native node"
    	sleep 1
    	kill_bg $CPID    
	
	break
    fi
    #echo "Closing native node"
    sleep 1
    kill_bg $CPID

    #echo "Closing Californium"
    #sleep 1
    #kill_bg $CALID
    
    rm node.log
    rm node.err
    rm californium.log
    rm californium.err
done


if grep -q 'OK' californium.log ; then
  cp californium.err $BASENAME.testlog;
  printf "%-32s TEST OK\n" "$BASENAME" | tee $BASENAME.testlog;
else
  echo "==== make.log ====" ; cat make.log;
  echo "==== make.err ====" ; cat make.err;
  echo "==== node.log ====" ; cat node.log;
  echo "==== node.err ====" ; cat node.err;
  echo "==== leshan.log ====" ; cat californium.log;
  echo "==== leshan.err ====" ; cat californium.err;
  echo "==== $BASENAME.log ====" ; cat $BASENAME.log;

  printf "%-32s TEST FAIL\n" "$BASENAME" | tee $BASENAME.testlog;
fi

rm make.log
rm make.err
rm node.log
rm node.err
rm californium.log
rm californium.err

# We do not want Make to stop -> Return 0
# The Makefile will check if a log contains FAIL at the end
exit 0
