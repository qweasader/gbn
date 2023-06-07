###############################################################################
# OpenVAS Vulnerability Test
#
# Jenkins Multiple Vulnerabilities (Oct 2017) - Windows
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112107");
  script_version("2021-10-12T09:28:32+0000");

  script_cve_id("CVE-2017-1000393", "CVE-2017-1000394", "CVE-2017-1000395", "CVE-2017-1000396", "CVE-2017-1000398",
                "CVE-2017-1000399", "CVE-2017-1000400", "CVE-2017-1000401", "CVE-2012-6153");

  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-10-12 09:28:32 +0000 (Tue, 12 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-08 22:24:00 +0000 (Wed, 08 May 2019)");
  script_tag(name:"creation_date", value:"2017-11-07 10:05:00 +0100 (Tue, 07 Nov 2017)");

  script_name("Jenkins Multiple Vulnerabilities (Oct 2017) - Windows");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2017-10-11/");

  script_tag(name:"summary", value:"Jenkins is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - arbitrary shell command execution

  - bundling vulnerable libraries

  - disclosing various information

  - sending form validation for passwords via GET");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain sensitive information,
  and execute arbitrary code.");

  script_tag(name:"affected", value:"Jenkins LTS 2.73.1 and prior, Jenkins weekly up to and including 2.83.");

  script_tag(name:"solution", value:"Upgrade to Jenkins weekly to 2.84 or later / Jenkins LTS to 2.73.2 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
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
  if( version_is_less( version:version, test_version:"2.73.2" ) ) {
    vuln = TRUE;
    fix = "2.73.2";
  }
} else {
  if( version_is_less( version:version, test_version:"2.84" ) ) {
    vuln = TRUE;
    fix = "2.84";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:location );
  security_message( port:port, data:report, proto:proto );
  exit( 0 );
}

exit( 99 );
