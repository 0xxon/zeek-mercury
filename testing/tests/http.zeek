# @TEST-DOC: basic test verifying http.log
# @TEST-EXEC: zeek -C -r $ZEEKTRACES/http/bro.org.pcap $PACKAGE %INPUT
# @TEST-EXEC: btest-diff http.log
