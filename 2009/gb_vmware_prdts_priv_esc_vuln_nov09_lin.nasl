# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801143");
  script_version("2024-02-08T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-11-05 12:25:48 +0100 (Thu, 05 Nov 2009)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2267");
  script_name("VMware Products Guest Privilege Escalation Vulnerability (Nov 2009) - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37172");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36841");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3062");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Oct/1023082.html");
  script_xref(name:"URL", value:"http://lists.vmware.com/pipermail/security-announce/2009/000069.html");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2009-0015.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_vmware_prdts_detect_lin.nasl");
  script_mandatory_keys("VMware/Linux/Installed");

  script_tag(name:"impact", value:"Local attacker can exploit this issue to gain escalated privileges in a guest
  virtual machine.");

  script_tag(name:"affected", value:"VMware Server version 2.0.x prior to 2.0.2 Build 203138,
  VMware Server version 1.0.x prior to 1.0.10 Build 203137,
  VMware Player version 2.5.x prior to 2.5.3 Build 185404,
  VMware Workstation version 6.5.x prior to 6.5.3 Build 185404 on Linux.");

  script_tag(name:"insight", value:"An error occurs while setting the exception code when a '#PF' (page fault)
  exception arises and can be exploited to gain escalated privileges within the VMware guest.");

  script_tag(name:"solution", value:"Upgrade your VMWare product according to the referenced vendor advisory.");

  script_tag(name:"summary", value:"VMWare product(s) are prone to a privilege escalation vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

if(!get_kb_item("VMware/Linux/Installed")){
  exit(0);
}

# VMware Player
vmplayerVer = get_kb_item("VMware/Player/Linux/Ver");
if(vmplayerVer)
{
  if(version_in_range(version:vmplayerVer, test_version:"2.5", test_version2:"2.5.2"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

# VMware Workstation
vmworkstnVer = get_kb_item("VMware/Workstation/Linux/Ver");
if(vmworkstnVer)
{
  if(version_in_range(version:vmworkstnVer, test_version:"6.5", test_version2:"6.5.2"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vmserverVer = get_kb_item("VMware/Server/Linux/Ver");
if(vmserverVer)
{
  if(version_in_range(version:vmserverVer, test_version:"1.0", test_version2:"1.0.9")||
     version_in_range(version:vmserverVer, test_version:"2.0", test_version2:"2.0.1")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
