# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:h2o_project:h2o";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140823");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-02-27 16:27:54 +0700 (Tue, 27 Feb 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-26 16:03:00 +0000 (Tue, 26 Feb 2019)");

  script_cve_id("CVE-2016-4864");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("H2O HTTP Server DoS Vulnerability-02");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_h2o_http_server_detect.nasl");
  script_mandatory_keys("h2o/installed");

  script_tag(name:"summary", value:"H2O allows remote attackers to cause a denial-of-service (DoS) via format
string specifiers in a template file via fastcgi, mruby, proxy, redirect or reproxy.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"H2O version 2.0.3 and prior.");

  script_tag(name:"solution", value:"Update to version 2.0.4 or later.");

  script_xref(name:"URL", value:"https://github.com/h2o/h2o/issues/1077");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
