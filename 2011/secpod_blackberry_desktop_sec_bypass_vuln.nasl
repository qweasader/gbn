# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.902329");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)");
  script_cve_id("CVE-2010-2603");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_name("BlackBerry Desktop Software Information Disclosure Vulnerability");


  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_blackberry_desktop_software_detect_win.nasl");
  script_mandatory_keys("BlackBerry/Desktop/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive information
  that may lead to further attacks.");
  script_tag(name:"affected", value:"BlackBerry Desktop Software version 4.7 through 6.0");
  script_tag(name:"insight", value:"The flaw is due to a 'weak password method' used in the BlackBerry
  Desktop Software, which allows to conduct brute force guessing attacks to
  decrypt the backup file.");
  script_tag(name:"solution", value:"Upgrade to the BlackBerry Desktop Software version 6.0.1 or later.");
  script_tag(name:"summary", value:"BlackBerry Desktop Software is prone to an information disclosure vulnerability.");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42657");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45434");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1024908");
  script_xref(name:"URL", value:"http://www.blackberry.com/btsc/search.do?cmd=displayKC&docType=kc&externalId=KB24764");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://uk.blackberry.com/services/desktop/desktop_pc.jsp");
  exit(0);
}


include("version_func.inc");

bbdVer = get_kb_item("BlackBerry/Desktop/Win/Ver");
if(!bbdVer){
  exit(0);
}

if(version_in_range(version:bbdVer, test_version:"4.7", test_version2:"6.0.0.43")){
  report = report_fixed_ver(installed_version:bbdVer, vulnerable_range:"4.7 - 6.0.0.43");
  security_message(port: 0, data: report);
}
