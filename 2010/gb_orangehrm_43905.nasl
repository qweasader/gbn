# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:orangehrm:orangehrm";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100851");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-10-12 12:50:34 +0200 (Tue, 12 Oct 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-4798");
  script_name("OrangeHRM 'uri' Parameter Local File Include Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_orangehrm_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("orangehrm/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43905");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/orangehrm/");

  script_tag(name:"summary", value:"OrangeHRM is prone to a local file-include vulnerability because it
  fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to obtain potentially
  sensitive information or to execute arbitrary local scripts in the context of the webserver process.
  This may allow the attacker to compromise the application and the computer. Other attacks are
  also possible.");

  script_tag(name:"affected", value:"OrangeHRM 2.6.0.1 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );
ver = infos['version'];
dir = infos['location'];

if( version_is_equal( version:ver, test_version:"2.6.1" ) ) {
  report = report_fixed_ver( installed_version:ver, fixed_version:"WillNotFix", install_path:dir );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );