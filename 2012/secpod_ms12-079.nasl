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
  script_oid("1.3.6.1.4.1.25623.1.0.902937");
  script_version("2024-07-10T05:05:27+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2012-2539");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-10 05:05:27 +0000 (Wed, 10 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-09 18:23:09 +0000 (Tue, 09 Jul 2024)");
  script_tag(name:"creation_date", value:"2012-12-12 10:23:39 +0530 (Wed, 12 Dec 2012)");
  script_name("Microsoft Office Word Remote Code Execution Vulnerability (2780642)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2760497");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56834");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2760498");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2760421");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2760416");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2760410");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2760405");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2687412");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-079");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl",
                      "gb_ms_office_web_apps_detect.nasl", "gb_ms_sharepoint_sever_n_foundation_detect.nasl",
                      "gb_smb_windows_detect.nasl");
  script_mandatory_keys("MS/Office/Prdts/Installed", "MS/SharePoint/Server_or_Foundation_or_Services/Installed");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a specially crafted word and RTF files.");

  script_tag(name:"affected", value:"- Microsoft Word Viewer

  - Microsoft Office 2003 Service Pack 3

  - Microsoft Office 2007 Service Pack 2

  - Microsoft Office 2007 Service Pack 3

  - Microsoft Office 2010 Service Pack 1

  - Microsoft Office Web Apps 2010 Service Pack 1

  - Microsoft SharePoint Server 2010 Service Pack 1

  - Microsoft Office Compatibility Pack Service Pack 2

  - Microsoft Office Compatibility Pack Service Pack 3");

  script_tag(name:"insight", value:"The flaw is due to an error when parsing Rich Text Format (RTF) data related
  to the listoverridecount and can be exploited to corrupt memory.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS12-079.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

# Microsoft Office Word 2003/2007/2010
winwordVer = get_kb_item("SMB/Office/Word/Version");
if(winwordVer)
{
  if(version_in_range(version:winwordVer, test_version:"11.0", test_version2:"11.0.8349") ||
     version_in_range(version:winwordVer, test_version:"12.0", test_version2:"12.0.6668.4999") ||
     version_in_range(version:winwordVer, test_version:"14.0", test_version2:"14.0.6129.4999"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

wordcnvVer = get_kb_item("SMB/Office/WordCnv/Version");
if(wordcnvVer)
{
  # Office Word Converter
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                             item:"ProgramFilesDir");
  if(path)
  {
    path = "\Microsoft Office\Office12";
    sysVer = fetch_file_version(sysPath:path, file_name:"Wordcnv.dll");
    if(sysVer)
    {
      if(version_in_range(version:sysVer, test_version:"12.0", test_version2:"12.0.6668.4999"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

wordviewVer = get_kb_item("SMB/Office/WordView/Version");
if(wordviewVer)
{
  if(version_in_range(version:wordviewVer, test_version:"11.0", test_version2:"11.0.8349"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

cpe_list = make_list("cpe:/a:microsoft:sharepoint_server", "cpe:/a:microsoft:office_web_apps");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];
cpe  = infos["cpe"];

## SharePoint Server 2010
if("cpe:/a:microsoft:sharepoint_server" >< cpe)
{
  ## SharePoint Server 2010 (wosrv)
  if(vers =~ "^14\..*")
  {
    key = "SOFTWARE\Microsoft\Office Server\14.0";
    file = "Msoserver.Dll"; # File is not mentioned in bulletin. Based on the after applying patch it is taken.
  }

  if(key && registry_key_exists(key:key) && file)
  {
    if(path = registry_get_sz(key:key, item:"InstallPath"))
    {
      path = path + "\WebServices\WordServer\Core";
      dllVer = fetch_file_version(sysPath:path, file_name:file);
      if(dllVer)
      {
        if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.6129.4999"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
    }
  }
}

## Microsoft Office Web Apps 2010 sp1
if("cpe:/a:microsoft:office_web_apps" >< cpe)
{
  ## Microsoft Office Web Apps 2010 sp1
  if(vers =~ "^14\..*")
  {
    path = get_kb_item("MS/Office/Web/Apps/Path");
    if(path && "Could not find the install" >!< path )
    {

      # File is not mentioned in bulletin. Based on the after applying patch it is taken.
      path = path + "\14.0\WebServices\ConversionService\Bin\Converter";
      dllVer = fetch_file_version(sysPath:path, file_name:"msoserver.dll");
      if(dllVer)
      {
        if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.6129.4999"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
    }
  }
}
