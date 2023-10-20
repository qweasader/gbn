# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:egroupware:egroupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108065");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2014-2027");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-02-01 09:00:00 +0100 (Wed, 01 Feb 2017)");
  script_name("EGroupware 'unserialize()' Multiple PHP Code Execution Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_egroupware_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("egroupware/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65651");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2014/02/19/3");
  script_xref(name:"URL", value:"http://www.egroupware.org/");

  script_tag(name:"summary", value:"EGroupware is prone to multiple remote PHP code-execution vulnerabilities.");

  script_tag(name:"impact", value:"Successfully exploiting these issues will allow attackers to execute arbitrary
  code within the context of the application.");

  script_tag(name:"affected", value:"EGroupware 1.8.005 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"Upgrade to EGroupware 1.8.006.20140217 or later");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

# Version is only exposed as 1.8.006 without the date
if( version_is_less( version:vers, test_version:"1.8.006" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.8.006.20140217" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
