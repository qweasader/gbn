# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/a:cisco:identity_services_engine';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106452");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-12-08 15:34:12 +0700 (Thu, 08 Dec 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-22 18:32:00 +0000 (Thu, 22 Dec 2016)");

  script_cve_id("CVE-2016-9214");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Identity Services Engine Cross-Site Scripting Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_ise_version.nasl");
  script_mandatory_keys("cisco_ise/version");

  script_tag(name:"summary", value:"Cisco Identity Services Engine (ISE) contains a vulnerability that could
allow an unauthenticated, remote attacker to conduct a cross-site scripting (XSS) attack against the user of the
web interface of the affected system.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient input validation of some
parameters passed via HTTP GET or POST methods.");

  script_tag(name:"impact", value:"An attacker may be able to exploit this vulnerability by intercepting the
user packets and injecting the malicious code.");

  script_tag(name:"affected", value:"Cisco Identity Services Engine software release 2.0(1.130)");

  script_tag(name:"solution", value:"See the vendors advisory for solutions.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161207-ise1");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version == "2.0.1.130") {
  report = report_fixed_ver(installed_version: version, fixed_version: 'See advisory');
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
