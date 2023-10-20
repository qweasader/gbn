# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:prime_infrastructure";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106897");
  script_cve_id("CVE-2017-6662");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_version("2023-07-14T16:09:27+0000");

  script_name("Cisco Prime Infrastructure XML Injection Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170621-piepnm1");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the web-based user interface of Cisco Prime Infrastructure
(PI) could allow an authenticated, remote attacker read and write access to information stored in the affected
system as well as perform remote code execution. The attacker must have valid user credentials.");

  script_tag(name:"insight", value:"The vulnerability is due to improper handling of XML External Entity (XXE)
entries when parsing an XML file. An attacker could exploit this vulnerability by convincing the administrator
of an affected system to import a crafted XML file with malicious entries which could allow the attacker to read
and write files and execute remote code within the application.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-29 17:47:00 +0000 (Mon, 29 Jul 2019)");
  script_tag(name:"creation_date", value:"2017-06-22 12:07:33 +0700 (Thu, 22 Jun 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_cisco_pis_version.nasl");
  script_mandatory_keys("cisco_pis/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE))
  exit(0);

affected = make_list(
  '1.2.0',
  '1.2.0.103',
  '1.2.1',
  '1.3.0',
  '1.3.0.20',
  '1.4.0',
  '1.4.0.45',
  '1.4.1',
  '1.4.2',
  '2.0.0',
  '2.1.0',
  '2.2.2',
  '2.2.3',
  '2.2.0',
  '3.0.0',
  '3.1.0.128',
  '3.1.4.0',
  '3.1.5.0',
  '3.1.0',
  '3.1.1',
  '3.2.0.0');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

