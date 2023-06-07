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
  script_oid("1.3.6.1.4.1.25623.1.0.900805");
  script_version("2022-02-22T15:13:46+0000");
  script_tag(name:"last_modification", value:"2022-02-22 15:13:46 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-07-23 21:05:26 +0200 (Thu, 23 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2578");
  script_name("Google Chrome Unicode String Denial Of Service Vulnerability");
  script_xref(name:"URL", value:"http://websecurity.com.ua/3338/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/505092/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation lets the attacker cause memory or CPU consumption,
  resulting in Denial of Service condition.");

  script_tag(name:"affected", value:"Google Chrome version 2.x to 2.0.172 on Windows.");

  script_tag(name:"insight", value:"Error occurs when application fails to handle user supplied input into the
  'write' method via a long Unicode string argument.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 4.1.249.1064 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Google Chrome is prone to a denial of service (DoS) vulnerability.");

  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_in_range(version:chromeVer, test_version:"2.0", test_version2:"2.0.172")) {
  report = report_fixed_ver(installed_version:chromeVer, vulnerable_range:"2.0 - 2.0.172");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
