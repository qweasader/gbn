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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900861");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-09-23 08:37:26 +0200 (Wed, 23 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-3263");
  script_name("Google Chrome RSS Or Atom Feed Cross-Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36770");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36416");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/506517/100/0/threaded");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2009/09/stable-channel-update.html");
  script_xref(name:"URL", value:"http://securethoughts.com/2009/09/exploiting-chrome-and-operas-inbuilt-atomrss-reader-with-script-execution-and-more/");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject arbitrary web
  script or HTML on the victim's system.");
  script_tag(name:"affected", value:"Google Chrome version 2.x and 3.x before 3.0.195.21 on Windows.");
  script_tag(name:"insight", value:"An XSS vulnerability exists when the application fails to handle 'RSS' and 'Atom'
  feed, related to the rendering of the application/rss+xml content type as
  'scripted content.'.");
  script_tag(name:"solution", value:"Upgrade to Google Chrom version 3.0.195.21 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Google Chrome is prone to a cross-site scripting (XSS) vulnerability.");
  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer)
  exit(0);

if(chromeVer =~ "^[23]\.")
{
  if(version_is_less(version:chromeVer, test_version:"3.0.195.21")){
    report = report_fixed_ver(installed_version:chromeVer, fixed_version:"3.0.195.21");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
