module Mercury::TLS;

# This is a quite hacky. We rely on the base SSL scripts of Zeek to be loaded and inject us there.

redef record SSL::Info += {
	mercury_tls_client_exts: vector of count &optional;
	mercury_tls_client_vals: vector of string &optional;
};

const TLS_GREASE: set[count] = {
	0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa,
	0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
};

const TLS_EXT_FIXED: set[count] = {
	0x0001, 0x0005, 0x0007, 0x0008, 0x0009, 0x000a, 0x000b, 0x000d,
	0x000f, 0x0010, 0x0011, 0x0018, 0x001b, 0x001c, 0x002b, 0x002d,
	0x0032, 0x5500
};

function degrease(elements: index_vec): string_vec
	{
	local out: string_vec;
	for ( i, element in elements )
		{
		if ( element in TLS_GREASE )
			out[i] = "0a0a";
		else
			out[i] = fmt("%04x", element);
		}
	return out;
	}

function degrease_single(val: count): count
	{
	return (val in TLS_GREASE) ? 0x0a0a : val;
	}

event ssl_extension(c: connection, is_client: bool, code: count, val: string) &priority=5
	{
	if ( ! is_client )
		return;

	if ( ! c$ssl?$mercury_tls_client_exts )	{
		c$ssl$mercury_tls_client_exts = vector();
		c$ssl$mercury_tls_client_vals = vector();
	}
	c$ssl$mercury_tls_client_exts[|c$ssl$mercury_tls_client_exts|] = code;
	c$ssl$mercury_tls_client_vals[|c$ssl$mercury_tls_client_vals|] = val;
	}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) &priority=5
	{
	local unsorted_ciphers = degrease(ciphers);
	local tls_ext_vec: string_vec = vector();
	if ( c$ssl?$mercury_tls_client_exts )
		{
		for ( i, ext in c$ssl$mercury_tls_client_exts )
			{
			if ( ext in TLS_EXT_FIXED )
				tls_ext_vec += fmt("(%04x%04x%s)", ext, |c$ssl$mercury_tls_client_vals[i]|, bytestring_to_hexstr(c$ssl$mercury_tls_client_vals[i]));
			else
				tls_ext_vec += fmt("(%04x)", degrease_single(ext));
			}
		}

	local tls_fp: string = fmt("tls/(%04x)(%s)(%s)", version, join_string_vec(unsorted_ciphers, ""), join_string_vec(tls_ext_vec, ""));
	# FIXME: this could be optimized to use the sort function that's part of mercury
	local tls_1_fp: string = fmt("tls/1/(%04x)(%s)[%s]", version, join_string_vec(unsorted_ciphers, ""), join_string_vec(sort(tls_ext_vec, strcmp), ""));
	print tls_fp;
	print tls_1_fp;
	}

# more hacky stuff

module SSL;

event ssl_extension(c: connection, is_client: bool, code: count, val: string)
	{
	set_session(c);
	}

