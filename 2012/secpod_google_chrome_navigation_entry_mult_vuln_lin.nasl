# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.902904");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2011-3924", "CVE-2011-3925", "CVE-2011-3926", "CVE-2011-3927",
                "CVE-2011-3928");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-01-25 13:11:21 +0530 (Wed, 25 Jan 2012)");
  script_name("Google Chrome Multiple Vulnerabilities - Jan12 (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47694/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51641");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1026569");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=108461");
  script_xref(name:"URL", value:"http://securityorb.com/2012/01/google-releases-chrome-16-0-912-77/");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2012/01/stable-channel-update_23.html");

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code or
  cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 16.0.912.77 on Linux");
  script_tag(name:"insight", value:"Multiple flaws are due to an:

  - Use-after-free error and it is related to DOM selections and DOM handling.

  - Use-after-free error in the Safe Browsing feature and it is related to
    a navigation entry and an interstitial page.

  - Heap-based buffer overflow in the tree builder, allows remote attackers
    to cause a denial of service.

  - Error in Skia, does not perform all required initialization of values.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 16.0.912.77 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"16.0.912.77")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"16.0.912.77");
  security_message(port:0, data:report);
}
