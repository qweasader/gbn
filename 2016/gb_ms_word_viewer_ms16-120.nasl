###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Word Viewer Remote Code Execution Vulnerabilities (3192884)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807372");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2016-3209", "CVE-2016-3262", "CVE-2016-3263", "CVE-2016-3396", "CVE-2016-7182");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:14:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-10-12 10:48:54 +0530 (Wed, 12 Oct 2016)");
  script_name("Microsoft Office Word Viewer Remote Code Execution Vulnerabilities (3192884)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-120.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to the windows
  True Type Font and  GDI+ libraries are improperly handles specially crafted
  embedded fonts.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Microsoft Word Viewer.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3118394");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93385");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93390");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93394");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93380");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93395");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-120");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/Office/WordView/Version");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("version_func.inc");


wordviewPath = get_kb_item("SMB/Office/WordView/Install/Path");
if(!wordviewPath){
  exit(0);
}

if(wordviewPath)
{
  wordviewVer = fetch_file_version(sysPath:wordviewPath, file_name:"gdiplus.dll");

  if(wordviewVer)
  {
    ## gdipluss.dll will update for https://support.microsoft.com/en-us/kb/3118394
    if(version_in_range(version:wordviewVer, test_version:"11.0", test_version2:"11.0.8434"))
    {
      report = 'File checked:     ' + wordviewPath + "gdiplus.dll" + '\n' +
               'File version:     ' + wordviewVer  + '\n' +
               'Vulnerable range: 11.0 - 11.0.8434 \n' ;
      security_message(data:report);
      exit(0);
    }
  }
}
