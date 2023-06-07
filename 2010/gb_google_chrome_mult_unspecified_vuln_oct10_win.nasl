###############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome multiple unspecified vulnerabilities - October 10(Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801460");
  script_version("2022-02-18T13:05:59+0000");
  script_tag(name:"last_modification", value:"2022-02-18 13:05:59 +0000 (Fri, 18 Feb 2022)");
  script_tag(name:"creation_date", value:"2010-10-07 09:42:58 +0200 (Thu, 07 Oct 2010)");
  script_cve_id("CVE-2010-1822", "CVE-2010-3729", "CVE-2010-3730");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-03 14:59:00 +0000 (Mon, 03 Aug 2020)");
  script_name("Google Chrome multiple unspecified vulnerabilities - October 10(Windows)");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2010/09/stable-beta-channel-updates_17.html");

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code
  via unspecified vectors.");
  script_tag(name:"affected", value:"Google Chrome version prior to 6.0.472.62");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - improper use of information about the origin of a document to manage
    properties.

  - Buffer mismanagement in the SPDY protocol.

  - Bad cast with malformed SVG.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 6.0.472.62 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple unspecified vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"6.0.472.62")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"6.0.472.62");
  security_message(port: 0, data: report);
}
