# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800135");
  script_version("2024-02-26T14:36:40+0000");
  script_tag(name:"last_modification", value:"2024-02-26 14:36:40 +0000 (Mon, 26 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-11-21 14:18:03 +0100 (Fri, 21 Nov 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5091", "CVE-2008-5092", "CVE-2008-5093", "CVE-2008-5094");
  script_name("Novell eDirectory Multiple Vulnerabilities (Nov 2008) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Aug/1020785.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30947");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Aug/1020786.html");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Aug/1020787.html");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Aug/1020788.html");
  script_xref(name:"URL", value:"http://www.novell.com/support/viewContent.do?externalId=3426981");
  script_xref(name:"URL", value:"http://www.novell.com/documentation/edir873/sp10_readme/netware/readme.txt");

  script_tag(name:"impact", value:"Successful exploitation allows remote code execution on the target
  machines or can allow disclosure of potentially sensitive information or can cause denial of service.");

  script_tag(name:"affected", value:"Novell eDirectory 8.8 SP2 and prior on Windows.");

  script_tag(name:"insight", value:"The flaws are due to:

  - boundary error in LDAP and NDS services.

  - boundary error in HTTP language header and HTTP content-length header.

  - HTTP protocol stack(HTTPSTK) that does not properly filter HTML code from
    user-supplied input.");

  script_tag(name:"solution", value:"Update to 8.8 Service Pack 3.");

  script_tag(name:"summary", value:"Novell eDirectory is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NDSonNT";
if(!registry_key_exists(key:key)){
  exit(0);
}

eDirVer = registry_get_sz(key:key, item:"DisplayName");
eDirVer = eregmatch(pattern:"Novell eDirectory ([0-9.]+ (SP[0-9]+)?)", string:eDirVer);
if(!isnull(eDirVer))
{
  eDirVer = ereg_replace(pattern:" ", string: eDirVer[1], replace:".");
  if(version_is_less(version:eDirVer, test_version:"8.8.SP3")){
    report = report_fixed_ver(installed_version:eDirVer, fixed_version:"8.8.SP3");
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
