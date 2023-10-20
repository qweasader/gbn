# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800356");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-13 14:39:10 +0100 (Fri, 13 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-6085");
  script_name("F-Secure Product(s) Integer Overflow Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32352");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31846");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Oct/1021073.html");
  script_xref(name:"URL", value:"http://www.f-secure.com/security/fsc-2008-3.shtml");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to craft the archive
  files with arbitrary codes and can cause integer overflow in the context
  of an affected application.");

  script_tag(name:"affected", value:"F-Secure AntiVirus 2008 and prior

  F-Secure AntiVirus Workstation

  F-Secure Internet Security 2008 and prior

  F-Secure Client Security

  F-Secure Internet Gatekeeper for Windows 6.61 and prior");

  script_tag(name:"insight", value:"The vulnerability is due to an integer overflow error while scanning
  contents of specially crafted RPM files inside the archives.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"summary", value:"F-Secure Product(s) is prone to an integer overflow vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Data Fellows\F-Secure")){
  exit(0);
}

# and Internet Security
fsPath = registry_get_sz(key:"SOFTWARE\Data Fellows\F-Secure\Anti-Virus",
                         item:"Path");
if(!fsPath)
{
  fsPath = registry_get_sz(key:"SOFTWARE\Data Fellows\F-Secure" +
                               "\Content Scanner Server", item:"Path");
  if(!fsPath){
    exit(0);
  }
}

fsPath = fsPath + "\fm4av.dll";
share = ereg_replace(pattern:"([a-zA-Z]):.*", replace:"\1$", string:fsPath);
file = ereg_replace(pattern:"[a-zA-Z]:(.*)", replace:"\1", string:fsPath);

dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

if(version_is_less(version:dllVer, test_version:"2.0.14340.7363")){
  report = report_fixed_ver(installed_version:dllVer, fixed_version:"2.0.14340.7363", install_path:fsPath);
  security_message(port: 0, data: report);
}
