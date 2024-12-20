# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:invision_power_services:invision_power_board";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100381");
  script_version("2024-03-04T14:37:58+0000");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-12-08 22:02:24 +0100 (Tue, 08 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Invision Power Board Local File Include and SQL Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37208");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/508207");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("invision_power_board_detect.nasl");
  script_mandatory_keys("invision_power_board/installed");

  script_tag(name:"summary", value:"Invision Power Board is prone to a local file-include vulnerability and
  multiple SQL-injection vulnerabilities because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit the local file-include vulnerability using
  directory-traversal strings to view and execute arbitrary local files within the context of the webserver
  process. Information harvested may aid in further attacks.

  The attacker can exploit the SQL-injection vulnerabilities to compromise the application, access or modify data,
  or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Invision Power Board 3.0.4 and 2.3.6 are vulnerable, other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if (version_is_equal(version: vers, test_version: "3.0.4") ||
    version_is_equal(version: vers, test_version: "2.3.6")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Unknown");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
