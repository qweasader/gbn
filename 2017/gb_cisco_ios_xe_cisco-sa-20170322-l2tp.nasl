# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios_xe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106687");
  script_cve_id("CVE-2017-3857");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2023-07-14T16:09:27+0000");

  script_name("Cisco IOS XE Software Layer 2 Tunneling Protocol Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170322-l2tp");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the Layer 2 Tunneling Protocol (L2TP) parsing function
of Cisco IOS XE Software could allow an unauthenticated, remote attacker to cause an affected device to reload.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient validation of L2TP packets. An
attacker could exploit this vulnerability by sending a crafted L2TP packet to an affected device.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to cause the affected device
to reload, resulting in a denial of service (DoS) condition.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-27 16:59:00 +0000 (Mon, 27 Jul 2020)");
  script_tag(name:"creation_date", value:"2017-03-23 10:05:36 +0700 (Thu, 23 Mar 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_cisco_ios_xe_consolidation.nasl");
  script_mandatory_keys("cisco/ios_xe/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

affected = make_list(
  '16.2.1',
  '3.1.0S',
  '3.1.1S',
  '3.1.2S',
  '3.1.4S',
  '3.1.4a.S',
  '3.10.0S',
  '3.10.1S',
  '3.10.1xb.S',
  '3.10.2S',
  '3.10.2t.S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.7S',
  '3.10.8S',
  '3.10.8a.S',
  '3.11.0S',
  '3.11.1S',
  '3.11.2S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.0a.S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.4S',
  '3.13.0S',
  '3.13.0a.S',
  '3.13.1S',
  '3.13.2S',
  '3.13.2a.S',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.5a.S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.1c.S',
  '3.15.2S',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.0c.S',
  '3.16.1S',
  '3.16.1a.S',
  '3.16.2S',
  '3.16.2a.S',
  '3.16.2b.S',
  '3.17.0S',
  '3.17.1S',
  '3.17.1a.S',
  '3.18.0S',
  '3.18.0a.S',
  '3.2.1S',
  '3.2.2S',
  '3.3.0S',
  '3.3.0SQ',
  '3.3.1S',
  '3.3.1SQ',
  '3.3.2S',
  '3.4.0S',
  '3.4.0SQ',
  '3.4.0a.S',
  '3.4.1S',
  '3.4.1SQ',
  '3.4.2S',
  '3.4.3S',
  '3.4.4S',
  '3.4.5S',
  '3.4.6S',
  '3.5.0S',
  '3.5.0SQ',
  '3.5.1S',
  '3.5.1SQ',
  '3.5.2S',
  '3.5.2SQ',
  '3.5.3SQ',
  '3.6.0S',
  '3.6.1S',
  '3.6.2S',
  '3.7.0S',
  '3.7.1S',
  '3.7.2S',
  '3.7.3S',
  '3.7.4S',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.0S',
  '3.9.1S',
  '3.9.2S');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
