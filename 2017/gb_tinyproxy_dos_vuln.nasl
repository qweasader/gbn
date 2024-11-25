# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:banu:tinyproxy";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140255");
  script_version("2024-03-12T05:06:30+0000");
  script_tag(name:"last_modification", value:"2024-03-12 05:06:30 +0000 (Tue, 12 Mar 2024)");
  script_tag(name:"creation_date", value:"2017-07-31 11:31:40 +0700 (Mon, 31 Jul 2017)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-31 15:15:00 +0000 (Tue, 31 Mar 2020)");

  script_cve_id("CVE-2017-11747");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tinyproxy < 1.10.0 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("sw_tinyproxy_http_detect.nasl");
  script_mandatory_keys("tinyproxy/detected");

  script_tag(name:"summary", value:"Tinyproxy is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Tinyproxy creates a /run/tinyproxy/tinyproxy.pid file after
  dropping privileges to a non-root account, which might allow local users to kill arbitrary
  processes by leveraging access to this non-root account for tinyproxy.pid modification before a
  root script executes a 'kill' command.");

  script_tag(name:"affected", value:"Tinyproxy versions prior to 1.10.0.");

  script_tag(name:"solution", value:"Update to version 1.10.0 or later.");

  script_xref(name:"URL", value:"https://github.com/tinyproxy/tinyproxy/releases/tag/1.10.0");
  script_xref(name:"URL", value:"https://github.com/tinyproxy/tinyproxy/issues/106");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.10.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.10.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
