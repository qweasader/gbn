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
  script_oid("1.3.6.1.4.1.25623.1.0.900310");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-02-20 17:40:17 +0100 (Fri, 20 Feb 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0352", "CVE-2009-0353");
  script_name("Mozilla Thunderbird Multiple Vulnerabilities Feb-09 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33799");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33598");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-01.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation may let the attacker cause remote code execution
  or may cause memory/application crash to conduct denial of service attack.");
  script_tag(name:"affected", value:"Thunderbird version prior to 2.0.0.21 on Windows.");
  script_tag(name:"insight", value:"Flaws are in vectors related to the layout engine and destruction of
  arbitrary layout objects by the 'nsViewManager::Composite' function.");
  script_tag(name:"solution", value:"Upgrade to Thunderbird version 2.0.0.21.");
  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

tbVer = get_kb_item("Thunderbird/Win/Ver");
if(!tbVer)
  exit(0);

if(version_is_less(version:tbVer, test_version:"2.0.0.21")){
  report = report_fixed_ver(installed_version:tbVer, fixed_version:"2.0.0.21");
  security_message(port: 0, data: report);
}