# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpipam:phpipam";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131024");
  script_version("2024-09-03T08:48:58+0000");
  script_tag(name:"last_modification", value:"2024-09-03 08:48:58 +0000 (Tue, 03 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-08-30 07:28:10 +0000 (Fri, 30 Aug 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("phpIPAM <= 1.6.0 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpipam_http_detect.nasl");
  script_mandatory_keys("phpipam/detected");

  script_tag(name:"summary", value:"phpIPAM is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"XSS in the following paths:

  - app/tools/subnet-masks/popup.php

  - app\admin\firewall-zones\zones-edit-network.php

  - app\admin\groups\edit-group.php

  - app\admin\import-export\import-load-data.php

  - app/admin/powerDNS/record-edit.php

  - app/admin/widgets/edit.php

  - app/tools/request-ip/index.php");

  script_tag(name:"affected", value:"phpIPAM version 1.6.0 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 30th August, 2024.
  Information regarding this issue will be updated once solution details are available.

  Note: The vendor has added a fix into the master repository with commit 'b131fb9'. This fix
  should be involved in the upcoming 1.6.1 release. Please see the referenced advisory for further
  information.");

  script_xref(name:"URL", value:"https://github.com/phpipam/phpipam/commit/b131fb99c9ada95b38e4cb2749ac599e42fad3d9");
  script_xref(name:"URL", value:"https://phpipam.net/documents/changelog/current/");
  script_xref(name:"URL", value:"https://github.com/phpipam/phpipam/issues/4145");
  script_xref(name:"URL", value:"https://github.com/phpipam/phpipam/issues/4146");
  script_xref(name:"URL", value:"https://github.com/phpipam/phpipam/issues/4147");
  script_xref(name:"URL", value:"https://github.com/phpipam/phpipam/issues/4148");
  script_xref(name:"URL", value:"https://github.com/phpipam/phpipam/issues/4149");
  script_xref(name:"URL", value:"https://github.com/phpipam/phpipam/issues/4150");
  script_xref(name:"URL", value:"https://github.com/phpipam/phpipam/issues/4151");

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

if (version_is_less_equal(version: version, test_version: "1.6.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See solution", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
