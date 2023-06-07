# SPDX-FileCopyrightText: 2005 George A. Theall
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mailenable:mailenable";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14712");
  script_version("2023-05-11T09:09:33+0000");
  script_tag(name:"last_modification", value:"2023-05-11 09:09:33 +0000 (Thu, 11 May 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MailEnable < 1.8 SMTP Connector Service DNS Lookup DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2004 George A. Theall");
  script_family("Denial of Service");
  script_dependencies("gb_mailenable_consolidation.nasl");
  script_mandatory_keys("mailenable/detected");

  script_tag(name:"summary", value:"MailEnable is prone to a denial of service (DoS) vulnerability
  in the SMTP connector service which will crash if it receives a DNS response with over 100 MX
  records.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"A remote attacker can exploit this to perform a DoS attack
  against the SMTP server on the target.");

  script_tag(name:"solution", value:"Update to version 1.8 (Standard Edition), 1.5e (Professional
  Edition) or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11144");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "1.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.8");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);