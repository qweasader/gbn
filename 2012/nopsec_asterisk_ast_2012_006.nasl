# SPDX-FileCopyrightText: 2012 NopSec Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:digium:asterisk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.110018");
  script_version("2023-12-19T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-19 05:05:25 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-06-19 11:43:12 +0100 (Tue, 19 Jun 2012)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"cvss_base", value:"6.5");

  script_cve_id("CVE-2012-2416");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk SIP Channel Driver DoS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2012 NopSec Inc.");
  script_dependencies("gb_digium_asterisk_sip_detect.nasl");
  script_mandatory_keys("digium/asterisk/detected");

  script_tag(name:"summary", value:"Asterisk is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"chan_sip.c in the SIP channel driver in Asterisk Open Source
  1.8.x before 1.8.11.1 and 10.x before 10.3.1 and Asterisk Business Edition C.3.x before C.3.7.4,
  when the trustrpid option is enabled, alLows remote authenticated users to cause a denial of
  service (daemon crash) by sending a SIP UPDATE message that triggers a connected-line update
  attempt without an associated channel.");

  script_tag(name:"solution", value:"Update to version 1.8.11.1 / 10.3.1 / C.3.7.4 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53205");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) )
  exit( 0 );

version = infos["version"];
proto = infos["proto"];

if( version_in_range( version:version, test_version:"1.8", test_version2:"1.8.11.1" ) ||
    version_in_range( version:version, test_version:"10", test_version2:"10.3.1" ) ||
    version =~ "^C\.3([^0-9]|$)" ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.8.11.1/10.3.1/C.3.7.4" );
  security_message( port:port, data:report, protocol:proto );
  exit( 0 );
}

exit( 99 );
