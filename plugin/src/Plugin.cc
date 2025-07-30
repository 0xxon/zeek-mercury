#include "config.h"
#include "Plugin.h"

namespace zeek::plugin::Mercury_NPF { Plugin plugin; }

using namespace zeek::plugin::Mercury_NPF;

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "Mercury::NPF";
	config.description = "Mercury NPF";
	config.version.major = VERSION_MAJOR;
	config.version.minor = VERSION_MINOR;
	config.version.patch = VERSION_PATCH;
	return config;
	}
