###############################################################################
# OpenVAS Vulnerability Test
#
# LibreOffice Graphic Object Loading Buffer Overflow Vulnerability (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803085");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-1149");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-12-24 16:32:25 +0530 (Mon, 24 Dec 2012)");
  script_name("LibreOffice Graphic Object Loading Buffer Overflow Vulnerability (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47244");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53570");
  script_xref(name:"URL", value:"http://www.libreoffice.org/advisories/cve-2012-1149");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_libreoffice_detect_macosx.nasl");
  script_mandatory_keys("LibreOffice/MacOSX/Version");
  script_tag(name:"insight", value:"An integer overflow error within the vclmi.dll module when allocating memory
  for an embedded image object allows attacker to crash the application.");
  script_tag(name:"solution", value:"Upgrade to LibreOffice version 3.5.3 or later.");
  script_tag(name:"summary", value:"LibreOffice is prone to a buffer overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
  service condition or execute arbitrary code.");
  script_tag(name:"affected", value:"LibreOffice version before 3.5.3 on Mac OS X");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

libreVer = get_kb_item("LibreOffice/MacOSX/Version");
if(!libreVer){
  exit(0);
}

if(version_is_less(version: libreVer, test_version:"3.5.3")){
  report = report_fixed_ver(installed_version:libreVer, fixed_version:"3.5.3");
  security_message(port:0, data:report);
}
