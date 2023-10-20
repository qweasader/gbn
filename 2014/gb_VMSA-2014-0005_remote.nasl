# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105038");
  script_cve_id("CVE-2014-3793");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2023-06-28T05:05:21+0000");
  script_name("VMware ESXi patches address a guest privilege escalation (VMSA-2014-0005) - Remote Version Check");
  script_tag(name:"last_modification", value:"2023-06-28 05:05:21 +0000 (Wed, 28 Jun 2023)");
  script_tag(name:"creation_date", value:"2014-06-02 11:04:01 +0100 (Mon, 02 Jun 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_vmware_esx_web_detect.nasl");
  script_mandatory_keys("VMware/ESX/build", "VMware/ESX/version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2014-0005.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable build is present on the target host.");

  script_tag(name:"insight", value:"a. Guest privilege escalation in VMware Tools
  A kernel NULL dereference vulnerability was found in VMware Tools
  running on Microsoft Windows 8.1. Successful exploitation of this
  issue could lead to an escalation of privilege in the guest operating
  system.

  The vulnerability does not allow for privilege escalation from the
  Guest Operating System to the host. This means that host memory can
  not be manipulated from the Guest Operating System.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware ESXi patches address a vulnerability in VMware Tools which could result in a privilege escalation on Microsoft Windows 8.1.");

  script_tag(name:"affected", value:"ESXi 5.5 without patch ESXi550-201403102-SG

  ESXi 5.1 without patch ESXi510-201404102-SG

  ESXi 5.0 without patch ESXi500-201405102-SG.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("vmware_esx.inc");

if( ! esxVersion = get_kb_item( "VMware/ESX/version" ) ) exit( 0 );
if( ! esxBuild = get_kb_item( "VMware/ESX/build" ) ) exit( 0 );

fixed_builds = make_array( "5.5.0", "1623387",
                           "5.1.0", "1743201",
                           "5.0.0", "1749766" );

if( ! fixed_builds[esxVersion] ) exit( 0 );

if( int( esxBuild ) < int( fixed_builds[esxVersion] ) ) {
  security_message(port:0, data:esxi_remote_report( ver:esxVersion, build:esxBuild, fixed_build:fixed_builds[esxVersion] ) );
  exit(0);
}

exit( 99 );
