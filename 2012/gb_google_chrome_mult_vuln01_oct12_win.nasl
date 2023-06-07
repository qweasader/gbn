###############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Multiple Vulnerabilities-01 Oct12 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802470");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-2900", "CVE-2012-5108", "CVE-2012-5109", "CVE-2012-5110",
                "CVE-2012-5111");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-10-15 11:14:26 +0530 (Mon, 15 Oct 2012)");
  script_name("Google Chrome Multiple Vulnerabilities-01 Oct12 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50872/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55830");
  script_xref(name:"URL", value:"https://www.securelist.com/en/advisories/50872");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2012/10/stable-channel-update.html");

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to execute arbitrary code
  with the privileges of a local user and cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 22.0.1229.92 on Windows");
  script_tag(name:"insight", value:"Multiple flaws are due to

  - A race condition error exists related to audio device handling.

  - An error exists related to Skia text rendering, ICU regex, compositor
    handling and plug-in crash monitoring for Pepper plug-ins.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 22.0.1229.92 or later.");
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

if(version_is_less(version:chromeVer, test_version:"22.0.1229.92")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"22.0.1229.92");
  security_message(port:0, data:report);
}
