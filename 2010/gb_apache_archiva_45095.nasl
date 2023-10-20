# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:archiva";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100924");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-12-01 13:10:27 +0100 (Wed, 01 Dec 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-3449", "CVE-2010-4408");

  script_name("Apache Archiva Cross Site Request Forgery Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45095");
  script_xref(name:"URL", value:"http://jira.codehaus.org/browse/MRM-1438");
  script_xref(name:"URL", value:"http://archiva.apache.org/docs/1.3.2/release-notes.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_apache_archiva_detect.nasl");
  script_mandatory_keys("apache_archiva/installed");
  script_require_ports("Services/www", 8080);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Updates are available. Please see the reference for more details.");
  script_tag(name:"summary", value:"Apache Archiva is prone to a cross-site request-forgery vulnerability.

Exploiting this issue may allow a remote attacker to perform certain administrative actions and gain unauthorized
access to the affected application. Other attacks are also possible.

The following versions are affected:

Archiva versions 1.0 through 1.0.3

Archiva versions 1.1 through 1.1.4

Archiva versions 1.2 through 1.2.2

Archiva versions 1.3 through 1.3.1");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: vers, test_version: "1", test_version2:"1.0.3") ||
    version_in_range(version: vers, test_version: "1.1", test_version2:"1.1.4") ||
    version_in_range(version: vers, test_version: "1.2", test_version2:"1.2.2") ||
    version_in_range(version: vers, test_version: "1.3", test_version2:"1.3.1")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
