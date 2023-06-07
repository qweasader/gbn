# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.903038");
  script_version("2022-05-25T07:40:23+0000");
  script_cve_id("CVE-2012-1766", "CVE-2012-1767", "CVE-2012-1768", "CVE-2012-1769",
                "CVE-2012-1770", "CVE-2012-1771", "CVE-2012-1772", "CVE-2012-1773",
                "CVE-2012-3106", "CVE-2012-3107", "CVE-2012-3108", "CVE-2012-3109",
                "CVE-2012-3110");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-05-25 07:40:23 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2012-08-15 15:41:59 +0530 (Wed, 15 Aug 2012)");
  script_name("MS Exchange Server WebReady Document Viewing Remote Code Execution Vulnerabilities (2740358)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2740358");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54497");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54500");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54504");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54506");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54511");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54531");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54536");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54541");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54543");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54546");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54548");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54550");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54554");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2012/2737111");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-058");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to run arbitrary code as
  LocalService on the affected Exchange server.");

  script_tag(name:"affected", value:"- Microsoft Exchange Server 2007 Service Pack 3

  - Microsoft Exchange Server 2010 Service Pack 1

  - Microsoft Exchange Server 2010 Service Pack 2");

  script_tag(name:"insight", value:"The flaws are caused when WebReady Document Viewer is used to preview a
  specially crafted file.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS12-058.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Exchange")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
file_name = "ClientAccess\Owa\Bin\DocumentViewing\TranscodingService.exe";

foreach version (make_list("Microsoft Exchange v14", "Microsoft Exchange"))
{
  key = key + version;
  exchangePath = registry_get_sz(key:key, item:"InstallLocation");

  if(exchangePath)
  {
    exeVer = fetch_file_version(sysPath:exchangePath, file_name:file_name);
    if(exeVer)
    {
      if(version_is_less(version:exeVer, test_version:"8.3.279.4") ||
         version_in_range(version:exeVer, test_version:"14.1", test_version2:"14.1.421.1") ||
         version_in_range(version:exeVer, test_version:"14.2", test_version2:"14.2.318.3"))
      {
        report = report_fixed_ver(installed_version:exeVer, file_checked:exchangePath + file_name, vulnerable_range:"< 8.3.279.4, 14.1 - 14.1.421.1, 14.2 - 14.2.318.3");
        security_message(port:0, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
