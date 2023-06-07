###############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Multiple Vulnerabilities - 02 Sep14 (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804483");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2014-3178", "CVE-2014-3179");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-09-16 15:43:46 +0530 (Tue, 16 Sep 2014)");

  script_name("Google Chrome Multiple Vulnerabilities - 02 Sep14 (Linux)");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Use-after-free error in rendering.

  - Various errors in internal audits, fuzzing and other initiatives.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to bypass certain security restrictions, and compromise a user's system.");

  script_tag(name:"affected", value:"Google Chrome version prior to 37.0.2062.120
  on Linux.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 37.0.2062.120
  or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/60988");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69709");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69710");
  script_xref(name:"URL", value:"https://src.chromium.org/viewvc/blink?revision=180539&view=revision");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2014/09/stable-channel-update_9.html");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chromeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"37.0.2062.120"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"37.0.2062.120");
  security_message(port:0, data:report);
  exit(0);
}
