# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nagios:nagiosxi";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100778");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-09-02 16:10:00 +0200 (Thu, 02 Sep 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Nagios XI < 2009R1.3 multiple vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42604");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/513248");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_nagios_XI_detect.nasl");
  script_mandatory_keys("nagiosxi/installed");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Reportedly, these issues have been fixed in Nagios XI 2009R1.3. Please
  see the references for more information.");

  script_tag(name:"summary", value:"Nagios XI is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"1. Nagios XI is prone to multiple cross-site scripting vulnerabilities
  because it fails to properly sanitize user-supplied input.

  An attacker may leverage these issues to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site. This may allow the attacker to steal cookie-based authentication
  credentials and to launch other attacks.

  2. Nagios XI is prone to an SQL-injection vulnerability because it
  fails to sufficiently sanitize user-supplied data before using it in
  an SQL query.

  Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities
  in the underlying database.");

  script_tag(name:"affected", value:"Versions prior to Nagios XI 2009R1.3 are vulnerable.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version: version, test_version: "2009R1.3")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"2009R1.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
