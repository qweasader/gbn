##############################################################################
# OpenVAS Vulnerability Test
#
# ISC BIND DNS64 Denial of Service Vulnerability - Linux
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
  script_oid("1.3.6.1.4.1.25623.1.0.810976");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-3136");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-20 12:15:00 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2017-05-23 11:40:43 +0530 (Tue, 23 May 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("ISC BIND DNS64 Denial of Service Vulnerability - Linux");

  script_tag(name:"summary", value:"ISC BIND is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to improper
  handling of queries when server is configured to use DNS64 and if the
  option 'break-dnssec yes' is in use.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial-of-service of a server.");

  script_tag(name:"affected", value:"ISC BIND 9.8.0 through 9.8.8-P1, 9.9.0
  through 9.9.9-P6, 9.9.10b1 through 9.9.10rc1, 9.10.0 through 9.10.4-P6,
  9.10.5b1 through 9.10.5rc1, 9.11.0 through 9.11.0-P3, 9.11.1b1 through
  9.11.1rc1, 9.9.3-S1 through 9.9.9-S8.");

  script_tag(name:"solution", value:"Update to ISC BIND version 9.9.9-P8
  or 9.9.10rc3 or 9.10.5rc3 or 9.11.1rc3 or 9.9.9-S10 or 9.10.4-P8 or
  9.11.0-P5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://kb.isc.org/docs/aa-01465");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97653");

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

if(version =~ "^9\.8\.") {
  if(revcomp(a: version, b: "9.8.8p2") < 0) {
    fix = "9.9.9-P8";
  }
}

else if(version =~ "^9\.9\.") {
  if(revcomp(a: version, b: "9.9.9p7") < 0) {
    fix = "9.9.9-P8";
  }

  else if((revcomp(a: version, b: "9.9.10b1") >= 0) && (revcomp(a: version, b: "9.9.10rc2") < 0)) {
    fix = "9.9.10rc3";
  }

  else if((revcomp(a: version, b: "9.10.0") >= 0) && (revcomp(a: version, b: "9.10.4p7") < 0)) {
    fix = "9.10.4-P8";
  }

  else if((revcomp(a: version, b: "9.10.5b1") >= 0) && (revcomp(a: version, b: "9.10.5rc2") < 0)) {
    fix = "9.10.5rc3";
  }

  else if((revcomp(a: version, b: "9.11.0") >= 0) && (revcomp(a: version, b: "9.11.0p4") < 0)) {
    fix = "9.11.0-P5";
  }

  else if((revcomp(a: version, b: "9.11.1b1") >= 0) && (revcomp(a: version, b: "9.11.1rc2") < 0)) {
    fix = "9.11.1rc3";
  }

  else if((revcomp(a: version, b: "9.9.3s1") >= 0) && (revcomp(a: version, b: "9.9.9s9") < 0)) {
    fix = "9.9.9-S10";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(data:report, port:port, proto:proto);
  exit(0);
}

exit(99);
