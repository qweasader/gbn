# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.902186");
  script_version("2022-02-18T13:05:59+0000");
  script_tag(name:"last_modification", value:"2022-02-18 13:05:59 +0000 (Fri, 18 Feb 2022)");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_cve_id("CVE-2010-1986", "CVE-2010-1987", "CVE-2010-1988");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Firefox Multiple Denial Of Service vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://websecurity.com.ua/4206/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/511329/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
  service.");

  script_tag(name:"affected", value:"Firefox version 3.6.3 and prior on windows XP SP3 and prior.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - A 'NULL' pointer dereference error when handling 'JavaScript' code that
  performs certain string concatenation and substring operations.

  - An out-of-bounds read errors when handling 'JavaScript' code that appends
  long strings to the content of a 'P' element, and performs certain other
  string concatenation and substring operations.

  - An error when handling 'JavaScript' code that creates multiple arrays
  containing elements with long string values, and then appends long strings
  to the content of a 'P' element.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple Denial of Service vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("secpod_reg.inc");
include("version_func.inc");

if(hotfix_check_sp(xp:4) <= 0){
  exit(0);
}

ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_is_less_equal(version:ffVer, test_version:"3.6.3")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
