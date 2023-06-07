# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.901197");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-04-01 15:39:52 +0200 (Fri, 01 Apr 2011)");
  script_cve_id("CVE-2011-1291", "CVE-2011-1292", "CVE-2011-1293",
                "CVE-2011-1294", "CVE-2011-1295", "CVE-2011-1296");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Google Chrome multiple vulnerabilities - March 11 (Windows)");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/03/stable-channel-update.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47029");

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser or cause denial-of-service condition.");
  script_tag(name:"affected", value:"Google Chrome version prior to 10.0.648.204 on Windows");
  script_tag(name:"insight", value:"- A buffer overflow error in base string handling.

  - An use-after-free error in the frame-loader implementation.

  - An Use-after-free error in the HTMLCollection implementation.

  - An error in the processing of CSS which leaves stale pointers behind.

  - An unspecified error related to broken node-hierarchy which leads to DOM
    tree corruption.

  - An error in the processing of SVG text which leaves stale pointers behind.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 10.0.648.204 or later.");
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

if(version_is_less(version:chromeVer, test_version:"10.0.648.204")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"10.0.648.204");
  security_message(port: 0, data: report);
}
