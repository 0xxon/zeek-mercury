##! Implements HTTP NPF

@load base/protocols/http

module Mercury::HTTP;

redef record HTTP::Info += {
	## Version of the http request
	mercury_request_version: string &optional;
	## Vector of header values for mercury
	mercury_headers: string &default="";
	## Mercury HTTP NPF
	npf: string &log &optional;
};

const HTTP_REQUEST_NAME_AND_VALUE: set[string] = {
	"ACCEPT",
	"ACCEPT-ENCODING",
	"CONNECTION",
	"DNT",
	"DPR",
	"UPGRADE-INSECURE-REQUESTS",
	"X-REQUESTED-WITH"
};

const HTTP_REQUEST_NAME_ONLY: set[string] = {
	"ACCEPT-CHARSET",
	"ACCEPT-LANGUAGE",
	"AUTHORIZATION",
	"CACHE-CONTROL",
	"HOST",
	"IF-MODIFIED-SINCE",
	"KEEP-ALIVE",
	"USER-AGENT",
	"X-FLASH-VERSION",
	"X-P2P-PEERDIST"
};

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
	{
	c$http$mercury_request_version = version;
	}

event http_header(c: connection, is_orig: bool, original_name: string, name: string, value: string)
	{
	if ( ! is_orig )
		return;

	if ( name in HTTP_REQUEST_NAME_AND_VALUE )
		c$http$mercury_headers += fmt("(%s3a20%s)", bytestring_to_hexstr(original_name), bytestring_to_hexstr(value));
	else if ( name in HTTP_REQUEST_NAME_ONLY )
		c$http$mercury_headers += fmt("(%s)", bytestring_to_hexstr(original_name));
	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
	{
	if ( ! is_orig || c$http?$npf || ! c$http?$mercury_request_version )
		return;

	c$http$npf = fmt("http/(%s)(485454502f%s)(%s)", bytestring_to_hexstr(c$http$method), bytestring_to_hexstr(c$http$mercury_request_version), c$http$mercury_headers);
	}
