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
  script_oid("1.3.6.1.4.1.25623.1.0.900396");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-07-23 21:05:26 +0200 (Thu, 23 Jul 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2462", "CVE-2009-2463", "CVE-2009-2464",
                "CVE-2009-2465", "CVE-2009-2466", "CVE-2009-2469",
                "CVE-2009-2471", "CVE-2009-2472");
  script_name("Mozilla Firefox Multiple Vulnerabilities July-09 (Windows)");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1972");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35765");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35766");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35769");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35770");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35772");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35773");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35775");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35776");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-34.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-37.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-39.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-40.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attacker to execute arbitrary code,
  memory corruption, XSS attacks and results in Denial of Service condition.");

  script_tag(name:"affected", value:"Mozilla Firefox version prior to 3.0.12 on Windows.");

  script_tag(name:"insight", value:"Multiple flaws are reported in Firefox, for more information refer below
  reference links.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.0.12 or 3.5 or later.");

  script_tag(name:"summary", value:"Firefox browser is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(!ffVer){
  exit(0);
}

if(version_is_less(version:ffVer, test_version:"3.0.12")){
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"3.0.12");
  security_message(port: 0, data: report);
}