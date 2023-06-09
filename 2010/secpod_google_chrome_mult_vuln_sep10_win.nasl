# Copyright (C) 2010 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901153");
  script_version("2022-02-18T13:05:59+0000");
  script_tag(name:"last_modification", value:"2022-02-18 13:05:59 +0000 (Fri, 18 Feb 2022)");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");
  script_cve_id("CVE-2010-1825", "CVE-2010-1824", "CVE-2010-1823",
                "CVE-2010-3417", "CVE-2010-3416", "CVE-2010-3415",
                "CVE-2010-3414", "CVE-2010-3413", "CVE-2010-3412",
                "CVE-2010-3411");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Google Chrome multiple vulnerabilities Sep-10 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41390/");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2010/09/stable-beta-channel-updates_14.html");

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to cause denial of service
  and possibly have unspecified other impact via unknown vectors.");

  script_tag(name:"affected", value:"Google Chrome version prior to 6.0.472.59 on Windows.");

  script_tag(name:"insight", value:"Multiple vulnerabilities are due to:

  - A use-after-free error exists when using document APIs during parsing.

  - A use-after-free error exists in the processing of SVG styles.

  - A use-after-free error exists in the processing of nested SVG elements.

  - A race condition exists in the console handling.

  - An unspecified error exists in the pop-up blocking functionality.

  - An unspecified error related to Geolocation can be exploited to corrupt memory.

  - The application does not prompt for extension history access.");

  script_tag(name:"solution", value:"Upgrade to the Google Chrome 6.0.472.59 or later.");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"6.0.472.59")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"6.0.472.59");
  security_message(port: 0, data: report);
}
