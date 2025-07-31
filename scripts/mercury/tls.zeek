##! Implements TLS NPF

@load base/protocols/ssl
@load base/protocols/quic

module Mercury::TLS;

export {
	const TLS_EXT_FIXED: set[count] = {
		0x0001, 0x0005, 0x0007, 0x0008, 0x0009, 0x000a, 0x000b, 0x000d,
		0x000f, 0x0010, 0x0011, 0x0018, 0x001b, 0x001c, 0x002b, 0x002d,
		0x0032, 0x5500
	};

	const TLS_EXT_INCLUDE: set[count] = {
		0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007,
		0x0008, 0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x000e, 0x000f,
		0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x0016, 0x0017, 0x0018,
		0x0019, 0x001a, 0x001b, 0x001c, 0x001d, 0x001e, 0x001f, 0x0020,
		0x0021, 0x0022, 0x0024, 0x0025, 0x0026, 0x0027, 0x0028, 0x002b,
		0x002c, 0x002d, 0x002e, 0x002f, 0x0030, 0x0031, 0x0032, 0x0033,
		0x0034, 0x0035, 0x0036, 0x0037, 0x0038, 0x0039, 0x003a, 0x003b,
		0x003c, 0x003d, 0x003e, 0x0a0a, 0x3374, 0x5500, 0x754f, 0x7550,
		0xfd00, 0xfe0d, 0xff00, 0xff01, 0xff03, 0xffa5, 0xffce
	};

	## replace greased elements with 0a0a
	global degrease: function(elements: index_vec): string_vec;

	## replace greased element with 0a0a
	global degrease_single: function(val: count): count;

	## fingerprint versions
	type TlsFingerprintVersion: enum {
		MERCURY_TLS_NONE,
		MERCURY_TLS,
		MERCURY_TLS_1,
		MERCURY_TLS_2
	};

	option fingerprint_version = MERCURY_TLS_NONE;
}

# This is a quite hacky. We rely on the base SSL scripts of Zeek to be loaded and inject us there.

redef record SSL::Info += {
	# tls client extension numbers, used for tracking
	mercury_tls_client_exts: vector of count &optional;
	# tls client extension values, used internally
	mercury_tls_client_vals: table[count] of string &optional;
	# Mercury TLS NPF
	npf: string &log &optional;
};

# quite directly adaptec/copied from libmerc/tls.cc. See COPYING
function is_private_extension(ext: count): bool
	{
	return ( (ext == 65280) || (ext >= 65282) );
	}

# quite directly adaptec/copied from libmerc/tls.cc. See COPYING
function is_unassigned_extension(ext: count): bool
	{
	return ( ext >=62 && ext <= 65279 && ! ( ( ext & 0x0f0f ) == 0x0a0a ) );
	}

function degrease(elements: index_vec): string_vec
	{
	local out: string_vec;
	for ( i, element in elements )
		{
		if ( ( element & 0x0f0f ) == 0x0a0a )
			out[i] = "0a0a";
		else
			out[i] = fmt("%04x", element);
		}
	return out;
	}

function degrease_single(val: count): count
	{
	return ( (val & 0x0f0f) == 0x0a0a) ? 0x0a0a : val;
	}

event ssl_extension(c: connection, is_client: bool, code: count, val: string) &priority=5
	{
	if ( ! is_client )
		return;

	local degreased = degrease_single(code);

	if ( ! c$ssl?$mercury_tls_client_exts )	{
		c$ssl$mercury_tls_client_exts = vector();
		c$ssl$mercury_tls_client_vals = table();
	}
	c$ssl$mercury_tls_client_exts[|c$ssl$mercury_tls_client_exts|] = degreased;
	c$ssl$mercury_tls_client_vals[degreased] = val;
	}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) &priority=5
	{
	# do not generate TLS NPFs for quic
	if ( c?$quic || fingerprint_version == MERCURY_TLS_NONE )
		return;

	local unsorted_ciphers = degrease(ciphers);
	local tls_ext_vec: string_vec = vector();


	if ( c$ssl?$mercury_tls_client_exts )
		{
		local extensions: vector of count;
		if ( fingerprint_version == MERCURY_TLS )
			extensions = c$ssl$mercury_tls_client_exts;
		else
			extensions = sort(c$ssl$mercury_tls_client_exts);

		for ( i, ext in extensions )
			{
			if ( fingerprint_version == MERCURY_TLS_2 )
				{
				# tls/2
				if ( ext in TLS_EXT_FIXED )
					tls_ext_vec += fmt("(%04x%04x%s)", ext, |c$ssl$mercury_tls_client_vals[ext]|, bytestring_to_hexstr(c$ssl$mercury_tls_client_vals[ext]));
				else if ( ext in TLS_EXT_INCLUDE )
					tls_ext_vec += fmt("(%04x)", ext);
				else if ( is_unassigned_extension(ext) )
					tls_ext_vec += "(003e)";
				else if ( is_private_extension(ext) )
					tls_ext_vec += "(ff00)";
				}
			else
				{
				# tls and tls/1
				if ( ext in TLS_EXT_FIXED )
					tls_ext_vec += fmt("(%04x%04x%s)", ext, |c$ssl$mercury_tls_client_vals[ext]|, bytestring_to_hexstr(c$ssl$mercury_tls_client_vals[ext]));
				else
					tls_ext_vec += fmt("(%04x)", ext);
				}
			}
		}

	local tls_fp: string;
	if ( fingerprint_version == MERCURY_TLS )
		tls_fp = fmt("tls/(%04x)(%s)(%s)", version, join_string_vec(unsorted_ciphers, ""), join_string_vec(tls_ext_vec, ""));
	else if ( fingerprint_version == MERCURY_TLS_1 )
		tls_fp = fmt("tls/1/(%04x)(%s)[%s]", version, join_string_vec(unsorted_ciphers, ""), join_string_vec(tls_ext_vec , ""));
	else if ( fingerprint_version == MERCURY_TLS_2 )
		tls_fp = fmt("tls/2/(%04x)(%s)[%s]", version, join_string_vec(unsorted_ciphers, ""), join_string_vec(tls_ext_vec, ""));;

	c$ssl$npf = tls_fp;
	}

# more hacky stuff

module SSL;

event ssl_extension(c: connection, is_client: bool, code: count, val: string)
	{
	set_session(c);
	}

