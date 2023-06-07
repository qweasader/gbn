###############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Multiple Denial of Service Vulnerabilities - May11 (Linux)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801891");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-05-26 10:47:46 +0200 (Thu, 26 May 2011)");
  script_cve_id("CVE-2011-1799", "CVE-2011-1800");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Google Chrome Multiple Denial of Service Vulnerabilities - May11 (Linux)");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/05/stable-channel-update.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47828");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47830");

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to execute arbitrary code in
  the context of the user running the application. Failed attacks may cause
  denial of service conditions.");
  script_tag(name:"affected", value:"Google Chrome version prior to 11.0.696.68 on Linux");
  script_tag(name:"insight", value:"- Bad variable casts in Chromium WebKit glue allows remote attackers to cause
    a denial of service or possibly have unspecified other impact.

  - Multiple integer overflows in the SVG Filters implementation in WebCore in
    WebKit allows remote attackers to cause a denial of service or possibly
    have unspecified other impact via unknown vectors.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 11.0.696.68 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple denial of service vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"11.0.696.68")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"11.0.696.68");
  security_message(port: 0, data: report);
}
