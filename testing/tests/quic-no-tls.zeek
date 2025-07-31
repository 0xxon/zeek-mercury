# @TEST-DOC: verify that no ssl entries are generated for a quic handshake
# @TEST-EXEC: zeek -C -r $ZEEKTRACES/quic/chromium-115.0.5790.110-api-cirrus-com.pcap $PACKAGE %INPUT
# @TEST-EXEC: btest-diff ssl.log

redef Mercury::TLS::fingerprint_version = Mercury::TLS::MERCURY_TLS;
