##############################################################################
# OpenVAS Vulnerability Test
#
# Squid Multiple Denial of Service Vulnerabilities April16 (Linux)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807794");
  script_version("2022-07-20T10:33:02+0000");
  script_cve_id("CVE-2016-3947", "CVE-2016-3948");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-07-20 10:33:02 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:14:00 +0000 (Mon, 28 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-04-18 18:23:23 +0530 (Mon, 18 Apr 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Squid Multiple DoS Vulnerabilities (SQUID-2016:3, SQUID-2016:4) - Linux");

  script_tag(name:"summary", value:"Squid is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A buffer overrun in the 'Icmp6::Recv' function in 'icmp/Icmp6.cc' script in the 'pinger' process.

  - An incorrect bounds checking while processing HTTP responses.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote HTTP servers to cause a
  denial of service, or write sensitive information to log files.");

  script_tag(name:"affected", value:"Squid version 3.x before 3.5.16 and 4.x before 4.0.8.");

  script_tag(name:"solution", value:"Update to version 3.5.16, 4.0.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/cve-2016-3948");
  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/cve-2016-3947");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2016_4.txt");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2016_3.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_squid_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("squid/detected", "Host/runs_unixoide");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(vers =~ "^[34]\.") {
  if(version_in_range(version:vers, test_version:"3.0.0", test_version2:"3.5.15")) {
    fix = "3.5.16";
    VULN = TRUE;
  }

  else if(version_in_range(version:vers, test_version:"4.0.0", test_version2:"4.0.7")) {
    fix = "4.0.8";
    VULN = TRUE;
  }

  if(VULN) {
    report = report_fixed_ver(installed_version:vers, fixed_version:fix);
    security_message(data:report, port:port);
    exit(0);
  }
}

exit(99);
