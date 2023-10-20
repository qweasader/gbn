# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141932");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2019-01-29 13:21:55 +0700 (Tue, 29 Jan 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse < 2.2.0.beta8 Missing HTML Escape Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to a vulnerability where title HTML for inline onebox are
not escaped.");

  script_tag(name:"affected", value:"Discourse before version 2.2.0.beta8.");

  script_tag(name:"solution", value:"Update to version 2.2.0.beta8.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://meta.discourse.org/t/discourse-2-2-0-beta8-release-notes/105915");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/commit/35b59cfa78c25eb53f76c21c47576ce30734fc07");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];

if (version_is_less(version: vers, test_version: "2.2.0") ||
    version_in_range(version: vers, test_version: "2.2.0.beta1", test_version2: "2.2.0.beta7")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "2.2.0.beta8", install_path: infos["location"]);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
