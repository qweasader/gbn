# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:knot:dns";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806811");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-01-08 11:38:56 +0530 (Fri, 08 Jan 2016)");
  script_name("Knot DNS Server Multiple Vulnerabilities");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_knot_dns_version_detect.nasl");
  script_mandatory_keys("KnotDNS/installed");

  script_xref(name:"URL", value:"https://gitlab.labs.nic.cz/labs/knot/raw/v1.6.3/NEWS");

  script_tag(name:"summary", value:"Knot DNS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - An out-of-bounds read error exists in the 'knot_rrset_rr_to_canonical'
    function.

  - An out-of-bounds read error exists in the zone parser due to improper
    handling of origin domain names.

  - An out-of-bounds read error exists in the 'rdata_seek' function.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain sensitive information or cause a denial of service.");

  script_tag(name:"affected", value:"Knot DNS version before 1.6.3");

  script_tag(name:"solution", value:"Upgrade to Knot DNS version 1.6.3
  or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.knot-dns.cz/pages/download.html");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) ) exit( 0 );

version = infos["version"];
proto = infos["proto"];

if( version_is_less( version:version, test_version:"1.6.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.6.3" );
  security_message( data:report, port:port, proto:proto );
  exit( 0 );
}

exit( 99 );
