##############################################################################
# OpenVAS Vulnerability Test
#
# ISC BIND 'buffer.c' Assertion Failure Denial of Service Vulnerability - Linux
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:isc:bind";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810263");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2016-2776");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");
  script_tag(name:"creation_date", value:"2017-01-06 12:10:51 +0530 (Fri, 06 Jan 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("ISC BIND 'buffer.c' Assertion Failure Denial of Service Vulnerability - Linux");

  script_tag(name:"summary", value:"ISC BIND is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the 'buffer.c' file
  in named in ISC BIND does not properly construct responses.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (assertion failure and daemon exit)
  via a crafted query.");

  script_tag(name:"affected", value:"ISC BIND before 9.9.9-P3, 9.10.x before
  9.10.4-P3, and 9.11.x before 9.11.0rc3.");

  script_tag(name:"solution", value:"Update to ISC BIND version 9.9.9-P3 or
  9.10.4-P3 or 9.11.0rc3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://kb.isc.org/docs/aa-01419");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93188");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_isc_bind_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("isc/bind/detected", "Host/runs_unixoide");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");
include("revisions-lib.inc");

if(isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if(!infos = get_app_full(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
proto = infos["proto"];
location = infos["location"];

if(version =~ "^9\.[0-9]\.") {
  if(revcomp(a: version, b: "9.9.9p3") < 0) {
    fix = "9.9.9-P3";
    VULN = TRUE;
  }
}

else if(version =~ "^9\.10") {
  if(revcomp(a: version, b: "9.10.4p3") < 0) {
    fix = "9.10.4-P3";
    VULN = TRUE;
  }
}

else if(version =~ "^9\.11") {
  if(revcomp(a: version, b: "9.11.0rc3") < 0) {
    fix = "9.11.0rc3";
    VULN = TRUE;
  }
}

if(VULN) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(data:report, port:port, proto:proto);
  exit(0);
}

exit(99);
