# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801709");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-14 07:39:17 +0100 (Fri, 14 Jan 2011)");
  script_cve_id("CVE-2007-5350");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Vulnerability in Windows Kernel Could Allow Elevation of Privilege (943078)");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/38729");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/26757");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2007/Dec/1019075.html");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2007/ms07-066");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code
  with kernel privileges.");

  script_tag(name:"affected", value:"Microsoft Windows Vista.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error in the way the Windows Advanced
  Local Procedure Call (ALPC) validates certain conditions of legacy reply paths.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS07-066.");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3) <= 0){
  exit(0);
}

if(hotfix_missing(name:"943078") == 0){
  exit(0);
}

dllPath = registry_get_sz(item:"PathName",
                          key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
if(!dllPath){
   exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                    string:dllPath + "\system32\ntoskrnl.exe");

exeVer = GetVer(file:file, share:share);
if(exeVer)
{
  if(hotfix_check_sp(winVista:3) > 0)
  {
    if(version_is_less(version:exeVer, test_version:"6.0.6000.16575")){
          report = report_fixed_ver(installed_version:exeVer, fixed_version:"6.0.6000.16575");
          security_message(port: 0, data: report);
    }
         exit(0);
  }
}
