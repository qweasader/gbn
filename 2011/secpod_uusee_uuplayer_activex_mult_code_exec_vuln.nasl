# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902563");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2011-08-31 10:37:30 +0200 (Wed, 31 Aug 2011)");
  script_cve_id("CVE-2011-2589", "CVE-2011-2590");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("UUSee UUPlayer ActiveX Control Multiple RCE Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44885");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48975");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68974");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68975");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary
code in the context of the application using the ActiveX control. Failed exploit
attempts will likely result in denial-of-service conditions.");
  script_tag(name:"affected", value:"UUSee UUPlayer 2010 6.11.0609.2");
  script_tag(name:"insight", value:"- A boundary error in the UUPlayer ActiveX control when handling
  the 'SendLogAction()' method can be exploited to cause a heap-based buffer
  overflow via an overly long argument.

  - An input validation error in the UUPlayer ActiveX control when handling
  the 'Play()' method can be exploited to execute an arbitrary program via
  a UNC path passed in the 'MPlayerPath' parameter.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"UUSee UUPlayer is prone to multiple remote code execution vulnerabilities.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\UUSEE";
if(!registry_key_exists(key:key)) {
  exit(0);
}

version = registry_get_sz(key:key, item:"DisplayVersion");
if(version)
{
  if(version_is_equal(version:version, test_version:"6.11.0609.2")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
