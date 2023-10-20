# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105487");
  script_cve_id("CVE-2015-8562");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2023-07-25T05:05:58+0000");

  script_name("Joomla! Core Remote Code Execution Vulnerability (Version Check)");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/79195");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/630-20151214-core-remote-code-execution-vulnerability.html");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows attackers to execute arbitrary code
in the context of the affected application.");

  script_tag(name:"vuldetect", value:"Check the installed version");

  script_tag(name:"insight", value:"Browser information is not filtered properly while saving the session values
into the database which leads to a Remote Code Execution vulnerability.");

  script_tag(name:"solution", value:"Update to 3.4.6 or later.");

  script_tag(name:"summary", value:"Joomla! is prone to remote code-execution vulnerability.");

  script_tag(name:"affected", value:"Joomla 1.5.0 through 3.4.5");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-12-17 11:34:17 +0100 (Thu, 17 Dec 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );

version = infos['version'];

if( version_in_range( version:version, test_version:"1.5.0", test_version2:"3.4.5" ) ) {
  report = 'Installed version: ' + version + '\n' +
           'Fixed version:     3.4.6';

  if( infos['location'] ) report += '\nInstall location:  ' + infos['location'] + '\n';

  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
