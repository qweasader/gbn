# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpbb:phpbb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100463");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-01-25 18:49:48 +0100 (Mon, 25 Jan 2010)");
  script_cve_id("CVE-2010-1630");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("phpBB Forum ID Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("phpbb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpBB/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37882");
  script_xref(name:"URL", value:"http://www.phpbb.com/community/viewtopic.php?f=14&p=9764445");

  script_tag(name:"impact", value:"Attackers can exploit this vulnerability to bypass certain security
  restrictions and gain unauthorized access to the affected application.");

  script_tag(name:"affected", value:"Versions prior to phpBB 3.0.5 are vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"phpBB is prone to a security-bypass vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"3.0.5" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.5" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
