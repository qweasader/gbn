###############################################################################
# OpenVAS Vulnerability Test
#
# Jenkins Multiple Vulnerabilities (Oct 2014) - Linux
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808268");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2014-3661", "CVE-2014-3662", "CVE-2014-3663", "CVE-2014-3664", "CVE-2014-3680",
                "CVE-2014-3681", "CVE-2014-3666", "CVE-2014-3667", "CVE-2013-2186", "CVE-2014-1869");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2016-08-05 09:47:29 +0530 (Fri, 05 Aug 2016)");

  script_name("Jenkins Multiple Vulnerabilities (Oct 2014) - Linux");

  script_tag(name:"summary", value:"Jenkins is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Jenkins does not properly prevent downloading of plugins.

  - Insufficient sanitization of packets over the CLI channel.

  - Password exposure in DOM.

  - Error in job configuration permission.

  - Thread exhaustion via vectors related to a CLI handshake.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information, to bypass bypass intended access
  restrictions and execute arbitrary code.");

  script_tag(name:"affected", value:"Jenkins main line 1.582 and prior, Jenkins LTS 1.565.2 and prior.");

  script_tag(name:"solution", value:"Jenkins main line users should update to 1.583,
  Jenkins LTS users should update to 1.565.3.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2014-10-01/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77953");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77963");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/88193");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77977");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77955");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77961");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_unixoide");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_full( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];
proto = infos["proto"];

if( get_kb_item( "jenkins/" + port + "/is_lts" ) ) {
  if( version_is_less( version:version, test_version:"1.565.3" ) ) {
    vuln = TRUE;
    fix = "1.565.3";
  }
} else {
  if( version_is_less( version:version, test_version:"1.583" ) ) {
    vuln = TRUE;
    fix = "1.583";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:location );
  security_message( port:port, data:report, proto:proto );
  exit( 0 );
}

exit( 99 );
