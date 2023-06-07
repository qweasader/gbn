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
  script_oid("1.3.6.1.4.1.25623.1.0.900819");
  script_version("2022-02-22T15:13:46+0000");
  script_tag(name:"last_modification", value:"2022-02-22 15:13:46 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-08-24 07:49:31 +0200 (Mon, 24 Aug 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2721", "CVE-2009-2722", "CVE-2009-2723",
                "CVE-2009-2724");
  script_name("Sun Java SE Multiple Unspecified Vulnerabilities");

  script_xref(name:"URL", value:"http://java.sun.com/j2se/1.5.0/ReleaseNotes.html");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-21-118667-22-1");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl", "gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win_or_Linux/installed");

  script_tag(name:"impact", value:"Impact is unknown.");

  script_tag(name:"affected", value:"Sun Java SE version 5.0 before Update 20");

  script_tag(name:"insight", value:"Refer to the SunSolve bugId 6406003/6429594/6444262 for more information.");

  script_tag(name:"summary", value:"Sun Java SE is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Java SE version 5 Update 20.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

jdkVer = get_kb_item("Sun/Java/JDK/Win/Ver");

if(jdkVer)
{
  if(version_in_range(version:jdkVer, test_version:"1.5", test_version2:"1.5.0.19"))
  {
    report = report_fixed_ver(installed_version:jdkVer, vulnerable_range:"1.5 - 1.5.0.19");
    security_message(port: 0, data: report);
    exit(0);
  }
}

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");

if(isnull(jreVer))
{
  jreVer = get_kb_item("Sun/Java/JRE/Linux/Ver");

  if(isnull(jreVer))
    exit(0);
}

if(jreVer)
{
  if(version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.19")){
    report = report_fixed_ver(installed_version:jreVer, vulnerable_range:"1.5 - 1.5.0.19");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
