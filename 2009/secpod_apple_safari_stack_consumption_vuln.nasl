# Copyright (C) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900870");
  script_version("2022-02-25T14:06:46+0000");
  script_tag(name:"last_modification", value:"2022-02-25 14:06:46 +0000 (Fri, 25 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-09-24 10:05:51 +0200 (Thu, 24 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3272");
  script_name("Apple Safari 'WebKit.dll' Stack Consumption Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9606");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/385690.php");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause stack consumption
  which may lead to the application crash.");

  script_tag(name:"affected", value:"Apple Safari version prior to 4.0.");

  script_tag(name:"insight", value:"The flaw is due to error in 'WebKit.dll' in WebKit which can be caused via
  JavaScript code that calls eval on a long string composed of 'A/' sequences.");

  script_tag(name:"solution", value:"Upgrade to Safari version 4.0 or later.");

  script_tag(name:"summary", value:"Apple Safari is prone to a stack consumption vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"4.30.17.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Safari 4.0 (4.30.17.0)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
