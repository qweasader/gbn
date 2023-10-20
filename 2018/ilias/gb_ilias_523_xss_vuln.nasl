# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112191");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-01-16 10:16:08 +0100 (Tue, 16 Jan 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-19 15:00:00 +0000 (Tue, 19 Jun 2018)");

  script_cve_id("CVE-2017-7583");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ILIAS < 5.2.3 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ilias_detect.nasl");
  script_mandatory_keys("ilias/installed");

  script_tag(name:"summary", value:"ILIAS eLearning before version 5.2.3 is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"insight", value:"It is possible to upload SVG files as media objects (e.g. in wiki pages)
which could be used to inject and execute JavaScript (persistent XSS).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"ILIAS up to and including version 5.2.2");

  script_tag(name:"solution", value:"Update to version 5.2.3 or later.");

  script_xref(name:"URL", value:"https://lists.ilias.de/pipermail/ilias-admins/2017-April/000024.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98733");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:ilias:ilias";

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.2.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
