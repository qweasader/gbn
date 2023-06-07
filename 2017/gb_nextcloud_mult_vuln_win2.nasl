# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106705");
  script_version("2023-05-15T09:08:55+0000");
  script_tag(name:"last_modification", value:"2023-05-15 09:08:55 +0000 (Mon, 15 May 2023)");
  script_tag(name:"creation_date", value:"2017-03-30 14:13:45 +0700 (Thu, 30 Mar 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:20:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2016-9465", "CVE-2016-9466");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Multiple Vulnerabilities (Windows)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("nextcloud/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Nextcloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Nextcloud is prone to multiple vulnerabilities:

  - Stored XSS in CardDAV image export. (CVE-2016-9465)

  - Reflected XSS in the Gallery application (CVE-2016-9466)");

  script_tag(name:"affected", value:"Nextcloud Server prior to 10.0.1");

  script_tag(name:"solution", value:"Update 10.0.1 or later versions.");

  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=nc-sa-2016-008");
  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=nc-sa-2016-009");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "10.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
