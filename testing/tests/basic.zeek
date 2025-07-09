# @TEST-DOC: basic test verifying ssl.log
# @TEST-EXEC: zeek -C -r $ZEEKTRACES/tls/chrome-1250-tls-x25519-kyber.pcap $PACKAGE %INPUT
# @TEST-EXEC: mv ssl.log ssl-chrome-1250-tls-x25519-kyber.log
# @TEST-EXEC: zeek -C -r $ZEEKTRACES/tls/tls1.2.trace $PACKAGE %INPUT
# @TEST-EXEC: mv ssl.log ssl-tls1.2.log
# @TEST-EXEC: btest-diff ssl-chrome-1250-tls-x25519-kyber.log
# @TEST-EXEC: btest-diff ssl-tls1.2.log
