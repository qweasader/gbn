# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107063");
  script_cve_id("CVE-2015-6289");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Cisco IOS Software TCP Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160620-isr");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the handling of remote TCP connections in Cisco IOS and Cisco IOS XE Software
  could allow an unauthenticated, remote attacker to cause a partial denial of service (DoS) condition
  due to low memory.

  The vulnerability is due to the handling of out-of-order, or otherwise invalid, TCP packets on a
  remote connection to an affected device. An attacker could exploit this vulnerability by connecting
  to the device and then sending crafted TCP packets that are out of order or have invalid flags. An
  exploit could allow the attacker to cause the device to report low-memory warnings, which could in
  turn cause a partial DoS condition. This vulnerability was initially found for Secure Shell Host
  (SSH) remote connections, but it could also affect other remote connections to the device.

  Cisco will release software updates that address this vulnerability. There are no workarounds that
  address this vulnerability.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-02 15:00:00 +0000 (Sat, 02 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-10-20 12:56:24 +0200 (Thu, 20 Oct 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_ssh_cisco_ios_get_version.nasl");
  script_mandatory_keys("cisco_ios/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
  '12.2(33)SCI4',
  '15.3(3)JBB2',
  '15.5(3)M');

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

