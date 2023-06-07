# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.805815");
  script_version("2022-08-02T10:11:24+0000");
  script_tag(name:"last_modification", value:"2022-08-02 10:11:24 +0000 (Tue, 02 Aug 2022)");
  script_tag(name:"creation_date", value:"2015-07-15 12:57:38 +0530 (Wed, 15 Jul 2015)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2015-1761", "CVE-2015-1762", "CVE-2015-1763");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Microsoft SQL Server Multiple Vulnerabilities (MS15-058)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("mssqlserver_detect.nasl");
  script_mandatory_keys("microsoft/sqlserver/detected");

  script_tag(name:"summary", value:"Microsoft SQL Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2015-1761: Privilege escalation

  - CVE-2015-1762, CVE-2015-1763: Authenticated remote code execution (RCE)");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to elevate
  their privileges or execute arbitrary code.");

  script_tag(name:"affected", value:"- Microsoft SQL Server 2008 for x86/x64 Service Pack 3

  - Microsoft SQL Server 2008 for x86/x64 Service Pack 4

  - Microsoft SQL Server 2008 R2 for x86/x64 Service Pack 2

  - Microsoft SQL Server 2008 R2 for x86/x64 Service Pack 3

  - Microsoft SQL Server 2012 for x86/x64 Service Pack 1

  - Microsoft SQL Server 2012 for x86/x64 Service Pack 2

  - Microsoft SQL Server 2014 for x86/x64");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3065718");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-058");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

cpe_list = make_list("cpe:/a:microsoft:sql_server:2014",
                     "cpe:/a:microsoft:sql_server:2012:sp1",
                     "cpe:/a:microsoft:sql_server:2012:sp2",
                     "cpe:/a:microsoft:sql_server:2008:r2:sp2",
                     "cpe:/a:microsoft:sql_server:2008:r2:sp3",
                     "cpe:/a:microsoft:sql_server:2008:sp3",
                     "cpe:/a:microsoft:sql_server:2008:sp4");

if (!infos = get_app_port_from_list(cpe_list:cpe_list))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if (!vers = get_kb_item("microsoft/sqlserver/" + port + "/version"))
  exit(0);

if (!get_app_location(cpe:cpe, port:port, nofork:TRUE))
  exit(0);

## MS SQL 2014 : sqlservr.exe : GDR x64 ==> 2014.120.2269.0  ; QFE x64 ==> 2014.120.2548.0
if (vers =~ "^12\.0") {
  if (version_in_range(version:vers, test_version:"12.0.2000.80", test_version2:"12.0.2268.0") ||
      version_in_range(version:vers, test_version:"12.0.2300", test_version2:"12.0.2547")) {
    report = report_fixed_ver(installed_version:vers,
                              vulnerable_range:"12.0.2000.80 - 12.0.2268.0 / 12.0.2300 - 12.0.2547");
    security_message(port:port, data:report);
    exit(0);
  }
}

## MS SQL 2012 SP1 : sqlservr.exe : GDR x64/x86 ==> 2011.110.3156.0  ; QFE x64/x86 ==> 2011.110.3513.0
if (vers =~ "^11\.0") {
  if (version_in_range(version:vers, test_version:"11.00.3000.00", test_version2:"11.0.3155") ||
      version_in_range(version:vers, test_version:"11.0.3300", test_version2:"11.0.3512")) {
    report = report_fixed_ver(installed_version:vers,
                              vulnerable_range:"11.00.3000.00 - 11.0.3155 / 11.0.3300 - 11.0.3512");
    security_message(port:port, data:report);
    exit(0);
  }
}

## MS SQL 2012 SP2 : sqlservr.exe : GDR x64/x86 ==> 2011.110.5343.0 ; QFE x64/x86 ==> 2011.110.5613.0
if (vers =~ "^11\.0") {
  if (version_in_range(version:vers, test_version:"11.0.5058.0", test_version2:"11.0.5342") ||
     version_in_range(version:vers, test_version:"11.0.5600", test_version2:"11.0.5612")) {
    report = report_fixed_ver(installed_version:vers,
                              vulnerable_range:"11.0.5058.0 - 11.0.5342 / 11.0.5600 - 11.0.5612");
    security_message(port:port, data:report);
    exit(0);
  }
}

## MS SQL 2008 R2 SP2 : sqlservr.exe : GDR x64/x86 ==> 2009.100.4042.0 ; QFE x64/x86 ==> 2009.100.4339.0
if (vers =~ "^10\.50") {
  if (version_in_range(version:vers, test_version:"10.50.4000.0", test_version2:"10.50.4041") ||
      version_in_range(version:vers, test_version:"10.50.4300", test_version2:"10.50.4338")) {
    report = report_fixed_ver(installed_version:vers,
                              vulnerable_range:"10.50.4000.0 - 10.50.4041 / 10.50.4300 - 10.50.4338");
    security_message(port:port, data:report);
    exit(0);
  }
}

## MS SQL 2008 R2 SP3 : sqlservr.exe : GDR x64/x86 ==> 2009.100.6220.0  ; QFE x64/x86 ==> 2009.100.6529.0
if (vers =~ "^10\.50") {
  if (version_in_range(version:vers, test_version:"10.50.6000.34", test_version2:"10.50.6219") ||
      version_in_range(version:vers, test_version:"10.50.6500", test_version2:"10.50.6528")) {
    report = report_fixed_ver(installed_version:vers,
                              vulnerable_range:"10.50.6000.34 - 10.50.6219 / 10.50.6500 - 10.50.6528");
    security_message(port:port, data:report);
    exit(0);
  }
}

## MS SQL 2008 SP3 : sqlservr.exe : GDR x64/x86 ==> 2007.100.5538.0  ; QFE x64/x86 ==> 2007.100.5890.0
if (vers =~ "^10\.0") {
  if (version_in_range(version:vers, test_version:"10.00.5500.00", test_version2:"10.0.5537") ||
      version_in_range(version:vers, test_version:"10.0.5750", test_version2:"10.0.5889")) {
    report = report_fixed_ver(installed_version:vers,
                              vulnerable_range:"10.00.5500.00 - 10.0.5537 / 10.0.5750 - 10.0.5889");
    security_message(port:port, data:report);
    exit(0);
  }
}

## MS SQL 2008 SP4 : sqlservr.exe : GDR x64/x86 ==> 2007.100.6241.0  ; QFE x64/x86 ==> 2007.100.6535.0
if (vers =~ "^10\.0") {
  if (version_in_range(version:vers, test_version:"10.00.6000.29", test_version2:"10.0.6240") ||
      version_in_range(version:vers, test_version:"10.0.6500", test_version2:"10.0.6534")) {
    report = report_fixed_ver(installed_version:vers,
                              vulnerable_range:"10.00.6000.29 - 10.0.6240 / 10.0.6500 - 10.0.6534");
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
