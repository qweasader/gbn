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
  script_oid("1.3.6.1.4.1.25623.1.0.900695");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-07-23 21:05:26 +0200 (Thu, 23 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2555", "CVE-2009-2556");
  script_name("Google Chrome Multiple Vulnerabilities - Jul09");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35844");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35722");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35723");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51801");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1924");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code with the  privileges of the logged on user by bypassing the sandbox
  and may crash the browser.");
  script_tag(name:"affected", value:"Google Chrome version prior to 2.0.172.37");
  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Heap overflow error when evaluating a specially crafted regular expression
    in Javascript within sandbox.

  - Error while allocating memory buffers for a renderer (tab) process.");
  script_tag(name:"solution", value:"Upgrade to Google Chrome version 2.0.172.37.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(chromeVer != NULL)
{
  if(version_is_less(version:chromeVer, test_version:"2.0.172.37")){
    report = report_fixed_ver(installed_version:chromeVer, fixed_version:"2.0.172.37");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
