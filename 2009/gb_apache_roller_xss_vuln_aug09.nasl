# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:roller";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800678");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-08-12 19:54:51 +0200 (Wed, 12 Aug 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-6879");

  script_name("Apache Roller 'q' Parameter Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/31523");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33110");
  script_xref(name:"URL", value:"http://issues.apache.org/roller/browse/ROL-1766");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_roller_detect.nasl");
  script_mandatory_keys("ApacheRoller/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject arbitrary
  HTML codes in the context of the affected web application.");

  script_tag(name:"affected", value:"Apache Roller version 2.x, 3.x and 4.0.");

  script_tag(name:"insight", value:"The issue is due to input validation error in 'q' parameter when performing
  a search. It is not properly sanitised before being returned to the user.");

  script_tag(name:"summary", value:"Apache Roller is prone to a Cross Site Scripting vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Apache Roller Version 4.0.1 or later or
  apply the patch via the references.");

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

if (version_is_less(version: version, test_version: "4.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
