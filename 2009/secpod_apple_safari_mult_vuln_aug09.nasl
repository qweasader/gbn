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
  script_oid("1.3.6.1.4.1.25623.1.0.900912");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-08-19 06:49:38 +0200 (Wed, 19 Aug 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2195", "CVE-2009-2196", "CVE-2009-2199",
                "CVE-2009-2200");
  script_name("Apple Safari Multiple Vulnerabilities - Aug09");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT3733");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36022");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36023");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36024");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36026");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36269/");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2009/Aug/msg00002.html");
  script_xref(name:"URL", value:"http://securethoughts.com/2009/08/hijacking-safari-4-top-sites-with-phish-bombs");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code, bypass
  security restrictions, gain sensitive information and can cause Denial of Service.");

  script_tag(name:"affected", value:"Apple Safari version prior to 4.0.3.");

  script_tag(name:"insight", value:"- An error in WebKit while parsing malicious floating point numbers can be
  exploited to cause buffer overflows.

  - An unspecified error in the Top Sites feature can be exploited to place a
  malicious  web site in the Top Sites view when a user visits a specially crafted web page.

  - Incomplete blacklist vulnerability in WebKit can be exploited via unspecified homoglyphs.

  - An error in WebKit in the handling of the 'pluginspage' attribute of the
  'embed' element can be exploited to launch arbitrary file: URLs and obtain
  sensitive information via a crafted HTML document.");

  script_tag(name:"solution", value:"Upgrade to Safari version 4.0.3.");

  script_tag(name:"summary", value:"Apple Safari Web Browser is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"4.31.9.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Safari 4.0.3 (4.31.9.1)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
