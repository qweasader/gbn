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
  script_oid("1.3.6.1.4.1.25623.1.0.900077");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-01-29 15:16:47 +0100 (Thu, 29 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0259");
  script_name("OpenOffice Denial of Service Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/6560");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33383");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/01/21/9");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_openoffice_detect_win.nasl");
  script_mandatory_keys("OpenOffice/Win/Ver");

  script_tag(name:"impact", value:"Successful remote exploitation could result in arbitrary code execution on
  the affected system which leads to application crash.");

  script_tag(name:"affected", value:"OpenOffice 1.1.2 to 1.1.5 on Windows.");

  script_tag(name:"insight", value:"OpenOffice application could trigger memory corruption due to a maliciously
  crafted .doc, .wri, or .rtf word 97 files.");

  script_tag(name:"solution", value:"Upgrade to the latest OpenOffice version.");

  script_tag(name:"summary", value:"OpenOffice is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

openVer = get_kb_item("OpenOffice/Win/Ver");
if(!openVer)
  exit(0);

if(version_in_range(version:openVer, test_version:"1.1.2", test_version2:"1.1.5")) {
  report = report_fixed_ver(installed_version:openVer, vulnerable_range:"1.1.2 - 1.1.5");
  security_message(port: 0, data: report);
}
