###############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Windows Kernel Memory Corruption Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802975");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-2897");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-09-28 12:49:03 +0530 (Fri, 28 Sep 2012)");
  script_name("Google Chrome Windows Kernel Memory Corruption Vulnerability");
  script_xref(name:"URL", value:"https://code.google.com/p/chromium/issues/detail?id=137852");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55676");

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to execute arbitrary code
  or cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 22.0.1229.79 on Windows 7");
  script_tag(name:"insight", value:"Unspecified error in application.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 22.0.1229.79 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to a memory corruption vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");

if(hotfix_check_sp(win7:2, win7x64:2) <= 0){
  exit(0);
}

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"22.0.1229.79")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"22.0.1229.79");
  security_message(port:0, data:report);
}
