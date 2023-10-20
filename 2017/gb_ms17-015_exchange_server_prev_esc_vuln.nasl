# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:exchange_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810705");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-0110");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-09 16:41:00 +0000 (Thu, 09 Aug 2018)");
  script_tag(name:"creation_date", value:"2017-03-15 11:17:25 +0530 (Wed, 15 Mar 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Exchange Server Remote Privilege Escalation Vulnerability (4013242)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS17-015.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists in the way that Microsoft
  Exchange Outlook Web Access (OWA) fails to properly handle web requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  an attacker to perform script/content injection attacks, and attempt to trick
  the user into disclosing sensitive information.");

  script_tag(name:"affected", value:"- Microsoft Exchange Server 2013 Cumulative Update 14

  - Microsoft Exchange Server 2016 Cumulative Update 3");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/4012178");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96621");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS17-015");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_exchange_server_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Exchange/Server/Ver");
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

exchangePath = get_app_location(cpe:CPE, skip_port:TRUE);
if(!exchangePath || "Could not find the install location" >< exchangePath){
  exit(0);
}

cum_update = get_kb_item("MS/Exchange/Cumulative/Update/no");

exeVer = fetch_file_version(sysPath:exchangePath, file_name:"Bin\ExSetup.exe");
if(exeVer)
{
  ## Exchange Server 2013
  if(version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.847.52"))
  {
    Vulnerable_range = "15.0 - 15.0.847.53";
    VULN = TRUE ;
  }

  ## Exchange Server 2013 CU 14
  else if(exeVer =~ "^(15.0)" && "Cumulative Update 14" >< cum_update)
  {
    if(version_is_less(version:exeVer, test_version:"15.0.1236.6"))
    {
      Vulnerable_range = "Less than 15.0.1236.6";
      VULN = TRUE ;
    }
  }

  ##Exchange Server 2016 CU 3
  else if(exeVer =~ "^(15.1)" && "Cumulative Update 3" >< cum_update)
  {
    if(version_is_less(version:exeVer, test_version:"15.1.544.30"))
    {
      Vulnerable_range = "Less than 15.1.544.30";
      VULN = TRUE ;
    }
  }
}

if(VULN)
{
  report = 'File checked:     ' + exchangePath + "\Bin\ExSetup.exe" + '\n' +
           'File version:     ' + exeVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
