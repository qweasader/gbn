###############################################################################
# OpenVAS Vulnerability Test
#
# Opera URL Processing Arbitrary Code Execution Vulnerability (Linux)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802654");
  script_version("2022-02-15T13:40:32+0000");
  script_cve_id("CVE-2012-3561");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-02-15 13:40:32 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2012-06-21 17:17:17 +0530 (Thu, 21 Jun 2012)");
  script_name("Opera URL Processing Arbitrary Code Execution Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027066");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1016/");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/unix/1164/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Linux/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code or cause a denial of service.");
  script_tag(name:"affected", value:"Opera version prior to 11.64 on Linux");
  script_tag(name:"insight", value:"The flaw is due to improper allocation of memory for URL strings,
  which allows remote attackers to execute arbitrary code or cause a denial
  of service (memory corruption and application crash) via a crafted string.");
  script_tag(name:"solution", value:"Upgrade to Opera version 11.64 or later.");
  script_tag(name:"summary", value:"Opera is prone to a code execution vulnerability.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"11.64")){
  report = report_fixed_ver(installed_version:operaVer, fixed_version:"11.64");
  security_message(port:0, data:report);
}
