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
  script_oid("1.3.6.1.4.1.25623.1.0.901018");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-09-16 15:34:19 +0200 (Wed, 16 Sep 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2139");
  script_name("OpenOffice EMF File Parser Remote Command Execution Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://www.debian.org/security/2009/dsa-1880");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36291");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_openoffice_detect_win.nasl");
  script_mandatory_keys("OpenOffice/Win/Ver");

  script_tag(name:"impact", value:"Successful remote exploitation could result in arbitrary code execution.");

  script_tag(name:"affected", value:"OpenOffice Version 2.x and 3.x on windows.");

  script_tag(name:"insight", value:"An Unspecified error occurs in the parser of EMF files when parsing certain
  crafted EMF files.");

  script_tag(name:"solution", value:"Upgrade to OpenOffice Version 3.1.1 or later.");

  script_tag(name:"summary", value:"OpenOffice is prone to a remote command execution vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

openVer = get_kb_item("OpenOffice/Win/Ver");
if(!openVer) {
  exit(0);
}

if(version_in_range(version:openVer, test_version:"2.0", test_version2:"3.1.9420")) {
   report = report_fixed_ver(installed_version:openVer, vulnerable_range:"2.0 - 3.1.9420");
   security_message(port: 0, data: report);
}
