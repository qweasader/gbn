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
  script_oid("1.3.6.1.4.1.25623.1.0.900305");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-02-18 15:32:11 +0100 (Wed, 18 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0490");
  script_name("Audacity Buffer Overflow Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33356");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33090");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7634");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_audacity_detect_win.nasl");
  script_mandatory_keys("Audacity/Win/Ver");
  script_tag(name:"impact", value:"Attacker may leverage this issue by executing arbitrary script code on
  the affected application, and can cause denial of service.");
  script_tag(name:"affected", value:"Audacity version prior to 1.3.6 on Windows.");
  script_tag(name:"insight", value:"Error in the String_parse::get_nonspace_quoted function in
  lib-src/allegro/strparse.cpp file that fails to validate user input data.");
  script_tag(name:"solution", value:"Upgrade to version 1.3.6 or later.");
  script_tag(name:"summary", value:"Audacity is prone to a buffer overflow
  vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

audacityVer = get_kb_item("Audacity/Win/Ver");
if(!audacityVer)
  exit(0);

if(version_is_less(version:audacityVer, test_version:"1.3.6")){
  report = report_fixed_ver(installed_version:audacityVer, fixed_version:"1.3.6");
  security_message(port: 0, data: report);
}
