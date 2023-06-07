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
  script_oid("1.3.6.1.4.1.25623.1.0.900831");
  script_version("2022-02-22T15:13:46+0000");
  script_tag(name:"last_modification", value:"2022-02-22 15:13:46 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-08-28 14:39:11 +0200 (Fri, 28 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2975");
  script_name("Mozilla Firefox 'document.location' Denial Of Service Vulnerability");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2009-08/0246.html");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2009-08/0234.html");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2009-08/0236.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause excessive memory
  consumption in the affected application and results in Denial of Service
  condition.");
  script_tag(name:"affected", value:"Mozilla Firefox version 3.5.2 on Windows XP.");
  script_tag(name:"insight", value:"The flaw is due to an incompletely configured protocol handler that does not
  properly implement setting of the 'document.location' property to a value
  specifying a protocol associated with an external application, which can
  be caused via vectors involving a series of function calls that set this
  property, as demonstrated by the 'chromehtml:' and 'aim:' protocols.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 3.6.3 or later");
  script_tag(name:"summary", value:"Firefox browser on Windows XP is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");


  exit(0);
}

include("secpod_reg.inc");
include("version_func.inc");

if(hotfix_check_sp(xp:4) <= 0){
  exit(0);
}

ffVer = get_kb_item("Firefox/Win/Ver");

if(isnull(ffVer))
{
  exit(0);
}

if(version_is_equal(version:ffVer, test_version:"3.5.2")){
  report = report_fixed_ver(installed_version:ffVer, vulnerable_range:"Equal to 3.5.2");
  security_message(port: 0, data: report);
}
