# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios_xe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106989");
  script_cve_id("CVE-2017-6665");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");

  script_name("Cisco IOS XE Software Autonomic Control Plane Channel Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170726-aniacp");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"summary", value:"A vulnerability in the Autonomic Networking feature of Cisco IOS XE Software
could allow an unauthenticated, adjacent attacker to reset the Autonomic Control Plane (ACP) of an affected system
and view ACP packets that are transferred in clear text within an affected system.");

  script_tag(name:"insight", value:"The vulnerability is due to unknown reasons. An attacker could exploit this
vulnerability by capturing and replaying ACP packets that are transferred within an affected system. A successful
exploit could allow the attacker to reset the ACP of an affected system, resulting in a denial of service (DoS)
condition.");

  script_tag(name:"impact", value:"A successful exploit could also allow the attacker to capture and view ACP
packets, which should have been encrypted over the ACP, in clear text.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-07-28 08:48:54 +0700 (Fri, 28 Jul 2017)");
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
  '16.5.1c',
  '16.6.1',
  '3.10.4S',
  '3.10.8S',
  '3.10.8a.S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.0a.S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.4S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.13.2a.S',
  '3.13.4S',
  '3.13.5S',
  '3.13.5a.S',
  '3.13.6S',
  '3.13.6a.S',
  '3.13.7a.S',
  '3.13.8S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.1a.S',
  '3.16.2S',
  '3.16.2a.S',
  '3.16.3S',
  '3.16.3a.S',
  '3.16.4S',
  '3.16.4a.S',
  '3.16.4d.S',
  '3.16.6S',
  '3.17.0S',
  '3.17.1S',
  '3.17.1a.S',
  '3.17.2S',
  '3.17.3S',
  '3.17.4S',
  '3.18.0S',
  '3.18.0SP',
  '3.18.0a.S',
  '3.18.1S',
  '3.18.1SP',
  '3.18.1b.SP',
  '3.18.2S',
  '3.18.2SP',
  '3.18.2a.SP',
  '3.18.3S',
  '3.18.3SP',
  '3.7.0E',
  '3.7.1E',
  '3.7.3E',
  '3.8.0E',
  '3.8.0EX',
  '3.8.1E',
  '3.8.2E',
  '3.8.3E',
  '3.9.0E',
  '3.9.1E');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "None");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
