# Copyright (C) 2011 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

CPE = 'cpe:/a:xymon:xymon';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902504");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-05-02 12:20:04 +0200 (Mon, 02 May 2011)");
  script_cve_id("CVE-2011-1716");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Xymon Monitor Unspecified Multiple Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/44036");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47156");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/66542");
  script_xref(name:"URL", value:"http://xymon.svn.sourceforge.net/viewvc/xymon/branches/4.3.2/Changes?revision=6673&view=markup");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_xymon_monitor_detect.nasl");
  script_mandatory_keys("xymon/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"Xymon Monitor versions 4.3.0 and prior.");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied input by
  multiple unspecified scripts which allows attackers to execute arbitrary
  HTML and script code on the web server.");

  script_tag(name:"solution", value:"Upgrade to Xymon Monitor version 4.3.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Xymon Monitor is prone to unspecified multiple cross site scripting vulnerabilities.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "4.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
