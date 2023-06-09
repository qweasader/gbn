###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Edge Multiple Vulnerabilities (3084525)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.807026");
  script_version("2020-11-16T11:08:42+0000");
  script_cve_id("CVE-2015-2441", "CVE-2015-2442", "CVE-2015-2446", "CVE-2015-2449");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-11-16 11:08:42 +0000 (Mon, 16 Nov 2020)");
  script_tag(name:"creation_date", value:"2016-01-08 16:38:38 +0530 (Fri, 08 Jan 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Edge Multiple Vulnerabilities (3084525)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-091.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple improper memory object handling errors

  - Microsoft Edge fails to use the Address Space Layout Randomization (ASLR)
    security feature");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code or cause a denial of service, bypass the
  Address Space Layout Randomization (ASLR) security feature, which helps
  protect users from a broad class of vulnerabilities.");

  script_tag(name:"affected", value:"Microsoft Edge on Microsoft Windows 10 x32/x64.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3081436");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-091");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_edge_detect.nasl", "gb_smb_lsc_fetch_file_ver.nasl");
  script_mandatory_keys("MS/Edge/Installed", "SMB/lsc_file_version_cache/edgehtml.dll/available");

  exit(0);
}

include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1) <= 0)
  exit(0);

infos = smb_get_fileversion_from_cache(file_name:"edgehtml.dll");
if(!infos)
  exit(0);

dllVer  = infos["version"];
dllPath = infos["location"];

if(hotfix_check_sp(win10:1, win10x64:1) > 0){
  if(version_is_less(version:dllVer, test_version:"11.0.10240.16428"))  {
    Vulnerable_range = "Less than 11.0.10240.16428";
    VULN = TRUE ;
  }
}

if(VULN){
  report = report_fixed_ver(file_checked:dllPath, file_version:dllVer, vulnerable_range:Vulnerable_range);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
