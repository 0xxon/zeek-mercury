##! Implements QUIC NPF

@load base/protocols/quic
@load ./tls

module Mercury::QUIC;

export {
	## Fingerprint versions
	type TlsFingerprintVersion: enum {
		MERCURY_QUIC,
		MERCURY_QUIC_1,
	};

	# Fingerprint version to use in the log
	option fingerprint_version = MERCURY_QUIC;
}

redef record QUIC::Info += {
	## The raw version of the initial quic packet
	mercury_raw_version: count &optional;
	## The quic transport parameters
	mercury_quic_transport_parameters: vector of string &optional;
	## Mercury_quic_npf
	npf: string &log &optional;
};

event QUIC::initial_packet(c: connection, is_orig: bool, version: count, dcid: string, scid: string) &priority=-1
	{
	c$quic$mercury_raw_version = version;
	}

event ssl_extension(c: connection, is_client: bool, code: count, val: string)
	{
	if ( ! is_client ||  ! c?$quic )
		return;

	if ( code != 0x39 && code != 0xffa5 )
		return;

	c$quic$mercury_quic_transport_parameters = Mercury::quic_transport_parameter(val);
	}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) &priority=5
	{
	# only generate for quic
	if ( !c?$quic || !c$quic?$mercury_raw_version )
		return;

	local unsorted_ciphers = Mercury::TLS::degrease(ciphers);

	local tls_ext_vec: string_vec = vector();

	if ( c$ssl?$mercury_tls_client_exts )
		{
		local extensions : vector of count = sort(c$ssl$mercury_tls_client_exts);

		for ( i, ext in extensions )
			{
			if ( ext in Mercury::TLS::TLS_EXT_FIXED )
				tls_ext_vec += fmt("(%04x%04x%s)", ext, |c$ssl$mercury_tls_client_vals[ext]|, bytestring_to_hexstr(c$ssl$mercury_tls_client_vals[ext]));
			else if ( ext == 0x39 || ext == 0xffa5 ) # quic_transport_parameters
				{
				local parameters: vector of string;
				if ( c$quic?$mercury_quic_transport_parameters )
					parameters = c$quic$mercury_quic_transport_parameters;

				tls_ext_vec += fmt("((0039)[%s])", join_string_vec(parameters, ""));
				}
			else
				{
				if ( fingerprint_version == MERCURY_QUIC )
					tls_ext_vec += fmt("(%04x)", ext);
				else
					{
					if ( ext in Mercury::TLS::TLS_EXT_INCLUDE )
						tls_ext_vec += fmt("(%04x)", ext);
					else if ( Mercury::TLS::is_unassigned_extension(ext) )
						tls_ext_vec += "(003e)";
					else if ( Mercury::TLS::is_private_extension(ext) )
						tls_ext_vec += "(ff00)";
					}
				}
			}
		}

	local npf: string;
	if ( fingerprint_version == MERCURY_QUIC )
		npf = fmt("quic/(%08x)(%04x)(%s)[%s]", c$quic$mercury_raw_version, version, join_string_vec(unsorted_ciphers, ""), join_string_vec(tls_ext_vec, ""));
	else
		npf = fmt("quic/1/(%08x)(%04x)(%s)[%s]", c$quic$mercury_raw_version, version, join_string_vec(unsorted_ciphers, ""), join_string_vec(tls_ext_vec, ""));

	c$quic$npf = npf;
	}
