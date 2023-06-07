###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco Webex Meetings Server Java Deserialization Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:cisco:webex_meetings_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809053");
  script_cve_id("CVE-2015-6420");
  script_version("2022-04-13T13:17:10+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2016-09-22 13:01:32 +0530 (Thu, 22 Sep 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Cisco Webex Meetings Server Java Deserialization Vulnerability");

  script_tag(name:"summary", value:"Cisco Webex Meetings Server is prone to a java deserialization vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insecure
  deserialization of user-supplied content by the affected software. An attacker
  could exploit this vulnerability by submitting crafted input to an application
  on a targeted system that uses the ACC library.");

  script_tag(name:"impact", value:"Successful exploitation allows an
  unauthenticated, remote attacker to execute arbitrary code.");

  script_tag(name:"affected", value:"Cisco Webex Meetings Server 2.5 before
  2.5.1.6183, 2.6 before 2.6.1.45 and 2.0 versions.");

  script_tag(name:"solution", value:"Update to Cisco Webex Meetings Server
  version 2.5.1.6183 or 2.6.1.1099 or 2.6.1.45 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCux17638");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/78872");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151209-java-deserialization");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_webex_meetings_server_detect.nasl");
  script_mandatory_keys("cisco/webex/meetings_server/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(vers =~ "^2\.6") {
  fix = "2.6.1.1099 or 2.6.1.45";
  VULN = TRUE;
}

else if(vers =~ "^2\.5") {
  fix = "2.5.1.6183";
  VULN = TRUE;
}

else if(vers =~ "^2\.0") {
  fix = "2.0.1.950 or 2.0.1.951 or 2.0.1.956";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix);
  security_message(port:port, data:report);
  exit(0);
}

exit(0);
