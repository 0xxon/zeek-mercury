# @TEST-DOC: basic test verifying ssl.log
# @TEST-EXEC: zeek -C -r $ZEEKTRACES/quic/chromium-115.0.5790.110-api-cirrus-com.pcap $PACKAGE %INPUT
# @TEST-EXEC: mv quic.log quic-chromium-115.0.5790.110-api-cirrus-com.log
# @TEST-EXEC: zeek -C -r $ZEEKTRACES/quic/firefox-102.13.0esr-blog-cloudflare-com.pcap $PACKAGE %INPUT
# @TEST-EXEC: mv quic.log quic-firefox-102.13.0esr-blog-cloudflare-com.pcap.log
# @TEST-EXEC: btest-diff quic-chromium-115.0.5790.110-api-cirrus-com.log
# @TEST-EXEC: btest-diff quic-firefox-102.13.0esr-blog-cloudflare-com.pcap.log

# @TEST-START-NEXT

redef Mercury::QUIC::fingerprint_version = Mercury::QUIC::MERCURY_QUIC_1;

