###############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Multiple Vulnerabilities-01 May13 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code or
  disclose sensitive information, conduct cross-site scripting attacks and
  compromise a users system.");
  script_tag(name:"affected", value:"Google Chrome version prior to 27.0.1453.93 on Windows");
  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 27.0.1453.93 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_oid("1.3.6.1.4.1.25623.1.0.803704");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-2836", "CVE-2013-2837", "CVE-2013-2838", "CVE-2013-2839",
                "CVE-2013-2840", "CVE-2013-2841", "CVE-2013-2842", "CVE-2013-2843",
                "CVE-2013-2844", "CVE-2013-2845", "CVE-2013-2846", "CVE-2013-2847",
                "CVE-2013-2848", "CVE-2013-2849");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-05-24 11:34:46 +0530 (Fri, 24 May 2013)");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Google Chrome Multiple Vulnerabilities-01 May13 (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/53430");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60062");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60063");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60064");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60065");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60066");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60067");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60068");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60069");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60070");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60071");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60072");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60073");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60074");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60076");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1028588");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2013/05/stable-channel-release.html");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"27.0.1453.93"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"27.0.1453.93");
  security_message(port: 0, data: report);
  exit(0);
}
