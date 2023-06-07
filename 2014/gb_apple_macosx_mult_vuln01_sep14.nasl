###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Mac OS X Multiple Vulnerabilities -01 Sep14
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804846");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2014-0015", "CVE-2014-1317", "CVE-2014-1375", "CVE-2014-1378",
                "CVE-2014-1355", "CVE-2014-1359", "CVE-2014-1356", "CVE-2014-1357",
                "CVE-2014-1358", "CVE-2014-1380", "CVE-2014-1381");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-09-19 10:06:15 +0530 (Fri, 19 Sep 2014)");

  script_name("Apple Mac OS X Multiple Vulnerabilities -01 Sep14");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to bypass security restrictions, disclose sensitive information,
  compromise the affected system, conduct privilege escalation and denial of
  service attacks.");

  script_tag(name:"affected", value:"Apple Mac OS X version before 10.9.4");

  script_tag(name:"solution", value:"Run Mac Updates. Please see the references for more information.");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT1338");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65270");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68272");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68274");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT6296");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1030505");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2014-06/0172.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.9\.");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer)
  exit(0);

if("Mac OS X" >< osName)
{
  if(version_in_range(version:osVer, test_version:"10.9.0", test_version2:"10.9.3"))
  {
    report = report_fixed_ver(installed_version:osVer, vulnerable_range:"10.9.0 - 10.9.3");
    security_message(port:0, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
