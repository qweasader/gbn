# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:identity_services_engine";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106895");
  script_cve_id("CVE-2017-6701");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("2023-07-25T05:05:58+0000");

  script_name("Cisco Identity Services Engine Cross-Site Scripting Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170621-ise");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the web application interface of the Cisco Identity
Services Engine (ISE) portal could allow an unauthenticated, remote attacker to conduct a stored cross-site
scripting (XSS) attack against a user of the web interface of an affected system.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient sanitization of user-supplied data
that is written to log files and displayed in certain web pages of the web interface of an affected device. An
attacker could exploit this vulnerability by successfully registering to a device and injecting script code as
part of a user-supplied value during the registration process.");

  script_tag(name:"impact", value:"An attacker could convince an administrator to visit an affected page or view
an affected log file to exploit the vulnerability. The injected script code would be executed in the affected
user's browser within the security context of the affected device.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-07 17:27:00 +0000 (Fri, 07 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-06-22 11:06:56 +0700 (Thu, 22 Jun 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_cisco_ise_version.nasl");
  script_mandatory_keys("cisco_ise/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version == '2.1.102.101') {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

