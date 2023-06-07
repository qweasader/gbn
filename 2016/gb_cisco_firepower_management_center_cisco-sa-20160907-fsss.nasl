###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco Firepower Management Center Cross-Site Scripting Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
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

CPE = "cpe:/a:cisco:firepower_management_center";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106230");
  script_cve_id("CVE-2016-6395");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_version("2021-10-14T10:01:27+0000");

  script_name("Cisco Firepower Management Center Cross-Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160907-fsss");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to version 6.1.0 or later.");

  script_tag(name:"summary", value:"A vulnerability in the web-based management interface of Cisco Firepower
  Management Center could allow an authenticated, remote attacker to conduct a cross-site scripting (XSS) attack
  against a user of the web-based management interface of an affected device.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient validation of user-supplied input
  by the web-based management interface of an affected device. An attacker could exploit this vulnerability by
  persuading a user of the interface to click a crafted link.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to execute arbitrary script code
  in the context of the interface or allow the attacker to access sensitive browser-based information.");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2021-10-14 10:01:27 +0000 (Thu, 14 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:32:00 +0000 (Mon, 28 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-09-08 10:11:15 +0700 (Thu, 08 Sep 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_firepower_management_center_consolidation.nasl");
  script_mandatory_keys("cisco/firepower_management_center/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "6.1.0")) {
  report = report_fixed_ver(  installed_version:version, fixed_version: "See advisory" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
