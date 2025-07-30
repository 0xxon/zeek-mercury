##! Implements QUIC NPF

@load ./tls

module Mercury::QUIC;

redef record QUIC::Info += {
	## The raw version of the initial quic packet
	mercury_raw_version: count &optional;
	## Mercury_quic_npf
	npf: string &log &optional;
};

event QUIC::initial_packet(c: connection, is_orig: bool, version: count, dcid: string, scid: string) &priority=-1
	{
	c$quic$mercury_raw_version = version;
	}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) &priority=5
	{
	# do not generate TLS NPFs for quic
	if ( !c?$quic || !c$quic?$mercury_raw_version )
		return;

	local unsorted_ciphers = Mercury::TLS::degrease(ciphers);

	local tls_ext_vec: string_vec = vector();

	if ( c$ssl?$mercury_tls_client_exts )
		{
		for ( i, ext in c$ssl$mercury_tls_client_exts )
			{
			local degreased_ext = Mercury::TLS::degrease_single(ext);
			if ( ext in Mercury::TLS::TLS_EXT_FIXED )
				tls_ext_vec += fmt("(%04x%04x%s)", ext, |c$ssl$mercury_tls_client_vals[i]|, bytestring_to_hexstr(c$ssl$mercury_tls_client_vals[i]));
			else if ( ext == 0x39 || ext == 0xffa5 ) # quic_transport_parameters
			else
				tls_ext_vec += fmt("(%04x)", degreased_ext);
			}
		}

	# FIXME: this could be optimized to use the sort function that's part of mercury
	local npf = fmt("quic/(%08x)(%04x)(%s)[%s]", c$quic$mercury_raw_version, version, join_string_vec(unsorted_ciphers, ""), join_string_vec(sort(tls_ext_vec, strcmp), ""));
	c$quic$npf = npf;
	print npf;
	}
