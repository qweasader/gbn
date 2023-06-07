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
  script_oid("1.3.6.1.4.1.25623.1.0.902312");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-09-23 08:13:58 +0200 (Thu, 23 Sep 2010)");
  script_cve_id("CVE-2010-2600");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("BlackBerry Desktop Software Insecure Library Loading Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41346");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43139");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Sep/1024425.html");
  script_xref(name:"URL", value:"http://www.blackberry.com/btsc/search.do?cmd=displayKC&docType=kc&externalId=KB24242");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_blackberry_desktop_software_detect_win.nasl");
  script_mandatory_keys("BlackBerry/Desktop/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a target application to
  execute arbitrary code on the target user's system.");
  script_tag(name:"affected", value:"BlackBerry Desktop Software version prior to 6.0.0.47");
  script_tag(name:"insight", value:"Desktop Manager passes an insufficiently qualified path to the Windows
  operating system when loading an external library.");
  script_tag(name:"solution", value:"Upgrade to the BlackBerry Desktop Software version 6.0.0.47 or later.");
  script_tag(name:"summary", value:"BlackBerry Desktop Software is prone to Insecure Library Loading Vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://uk.blackberry.com/services/desktop/desktop_pc.jsp");
  exit(0);
}


include("version_func.inc");

bbdVer = get_kb_item("BlackBerry/Desktop/Win/Ver");
if(!bbdVer){
  exit(0);
}

if(version_is_less(version:bbdVer, test_version:"6.0.0.47")){
  report = report_fixed_ver(installed_version:bbdVer, fixed_version:"6.0.0.47");
  security_message(port: 0, data: report);
}
