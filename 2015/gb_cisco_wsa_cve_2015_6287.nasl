# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:cisco:web_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105350");
  script_cve_id("CVE-2015-6287");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2023-07-25T05:05:58+0000");

  script_name("Cisco Web Security Appliance DNS Resolution Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/bugsearch/bug/CSCur07907");
  script_xref(name:"URL", value:"https://tools.cisco.com/bugsearch/bug/CSCur32005");

  script_tag(name:"impact", value:"An unauthenticated, remote attacker could exploit this vulnerability to cause a DoS condition due to DNS
name resolution failure through the affected device. This could result in the client receiving an HTTP 'Service Unavailable' error.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to the handling of DNS requests awaiting a DNS response when new, incoming DNS requests
are received. An attacker could exploit this vulnerability by sending TCP proxy traffic to the WSA at a high rate. An exploit could allow the attacker
to cause a partial DoS condition because DNS name resolution fails, which results in the client receiving a HTTP 503 'Service Unavailable' error.");

  script_tag(name:"solution", value:"Updates are available. Please see the vendor advisory for more information.");
  script_tag(name:"summary", value:"Cisco Web Security Appliance contains a vulnerability that could allow an unauthenticated, remote attacker to cause a denial of service condition.");
  script_tag(name:"affected", value:"Cisco WSA versions 8.0.6-078 and 8.0.6-115 are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-09-09 17:12:18 +0200 (Wed, 09 Sep 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_cisco_wsa_version.nasl");
  script_mandatory_keys("cisco_wsa/installed");
  exit(0);
}

include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

v = split( vers, sep:"-", keep:FALSE );
if( isnull( v[0] ) || isnull( v[1] ) ) exit( 0 );

if( v[0]  == "8.0.6" )
{
  if( int( v[1] ) < 119 )
  {
    report = 'Installed version: ' + vers + '\n' +
             'Fixed version:     8.0.6-119';
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

