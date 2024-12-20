# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801535");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-11-04 14:21:53 +0100 (Thu, 04 Nov 2010)");
  script_cve_id("CVE-2010-4149");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FreshWebMaster Fresh FTP Filename Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41798/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44072");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1010-exploits/freshftp-traversal.txt");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/directory_traversal_vulnerability_in_freshftp.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("FTP");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaw is due to an input validation error when downloading
directories containing files with directory traversal specifiers in the
filename.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Fresh FTP Client is prone to a directory traversal vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to download files
to an arbitrary location on a user's system.");
  script_tag(name:"affected", value:"FreshWebMaster Fresh FTP version 5.37 and prior");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FreshWebmaster FreshFTP_is1\";
if(!registry_key_exists(key:key)){
  exit(0);
}

ftpPath = registry_get_sz(key:key, item:"InstallLocation");
if(ftpPath)
{
  ftpPath1 = ftpPath + "\license.txt";
  radFile = smb_read_file(fullpath:ftpPath1, offset:0, count:500);
  if(!radFile)
  {
    readmePath = ftpPath + "\readme.txt";
    radFile = smb_read_file(fullpath:readmePath, offset:0, count:500);
  }

  if(radFile)
  {
    ftpVer = eregmatch(pattern:"FRESHFTP ver ([0-9.]+)", string:radFile, icase:1);
    if(ftpVer[1] != NULL)
    {
      if(version_is_less_equal(version:ftpVer[1], test_version:"5.37")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
  }
}
