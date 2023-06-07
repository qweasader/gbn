# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821244");
  script_version("2022-05-19T11:50:09+0000");
  script_cve_id("CVE-2022-1633", "CVE-2022-1634", "CVE-2022-1635", "CVE-2022-1636",
                "CVE-2022-1637", "CVE-2022-1638", "CVE-2022-1639", "CVE-2022-1640",
                "CVE-2022-1641");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-05-19 11:50:09 +0000 (Thu, 19 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-13 18:14:27 +0530 (Fri, 13 May 2022)");
  script_name("Google Chrome Security Update(stable-channel-update-for-desktop_10-2022-05) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple use after free errors.

  - Anappropriate implementation in Web Contents.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct execute arbitrary code, disclose sensitive information and cause
  denial of service condition.");

  script_tag(name:"affected", value:"Google Chrome version prior to 101.0.4951.64
  on Linux");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 101.0.4951.64
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/05/stable-channel-update-for-desktop_10.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"101.0.4951.64"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"101.0.4951.64", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
