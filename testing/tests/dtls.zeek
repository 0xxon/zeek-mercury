# @TEST-DOC: basic test verifying ssl.log
# @TEST-EXEC: zeek -C -r $ZEEKTRACES/tls/dtls1_0.pcap $PACKAGE %INPUT
# @TEST-EXEC: mv ssl.log ssl-dtls1_0.log
# @TEST-EXEC: zeek -C -r $ZEEKTRACES/tls/dtls13-cid.pcap $PACKAGE %INPUT
# @TEST-EXEC: mv ssl.log ssl-dtls13-cid.log
# @TEST-EXEC: btest-diff ssl-dtls1_0.log
# @TEST-EXEC: btest-diff ssl-dtls13-cid.log

redef Mercury::TLS::fingerprint_version = Mercury::TLS::MERCURY_TLS;

