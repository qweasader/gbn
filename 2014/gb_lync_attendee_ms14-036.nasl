###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Lync Attendee Remote Code Execution Vulnerabilities (2967487)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804462");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2014-1817", "CVE-2014-1818");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-06-11 13:51:38 +0530 (Wed, 11 Jun 2014)");
  script_name("Microsoft Lync Attendee Remote Code Execution Vulnerabilities (2967487)");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS14-036.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to:

  - An error within Unicode Scripts Processor.

  - An error within GDI+ when validating images.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the currently logged-in user, which may lead to a
  complete compromise of an affected computer.");

  script_tag(name:"affected", value:"Microsoft Lync Attendee 2010.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2963282");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67897");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67904");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2963284");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms14-036");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "secpod_ms_lync_detect_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Lync/Attendee/Ver", "MS/Lync/Attendee/path");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## For Microsoft Lync 2010 Attendee (admin level install)
## For Microsoft Lync 2010 Attendee (user level install)
if(get_kb_item("MS/Lync/Attendee/Ver"))
{
  path = get_kb_item("MS/Lync/Attendee/path");
  if(path)
  {
    oglVer = fetch_file_version(sysPath:path, file_name:"Ogl.dll");
    if(oglVer)
    {
      if(version_in_range(version:oglVer, test_version:"4.0", test_version2:"4.0.7577.4445"))
      {
        report = report_fixed_ver(installed_version:oglVer, vulnerable_range:"4.0 - 4.0.7577.4445", install_path:path);
        security_message(port:0, data:report);
        exit(0);
      }
    }
  }
}
