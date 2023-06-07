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
  script_oid("1.3.6.1.4.1.25623.1.0.900865");
  script_version("2022-02-22T15:13:46+0000");
  script_tag(name:"last_modification", value:"2022-02-22 15:13:46 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-09-22 10:03:41 +0200 (Tue, 22 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-7244");
  script_name("Mozilla Firefox 'window.print()' Denial Of Service Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://websecurity.com.ua/2456/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/506328/100/100/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"impact", value:"Successful attacks may result in Denial of Service condition on the victim's
  system.");
  script_tag(name:"affected", value:"Mozilla Firefox version 3.0.1 and prior on Windows.");
  script_tag(name:"insight", value:"Error exists when application fails to handle user supplied input when calling
  the 'window.print' function in a loop aka a 'printing DoS attack'.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 3.6.3 or later");
  script_tag(name:"summary", value:"Mozilla Firefox is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Firefox/Win/Ver");
if(!vers)
  exit(0);

if(version_is_less_equal(version:vers, test_version:"3.0.1")){
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"Less than or equal to 3.0.1");
  security_message(port: 0, data: report);
}
