# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:acme:thttpd";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140801");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-02-23 11:21:40 +0700 (Fri, 23 Feb 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-13 14:47:00 +0000 (Tue, 13 Mar 2018)");

  script_cve_id("CVE-2017-17663");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("thttpd Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_thttpd_detect.nasl");
  script_mandatory_keys("thttpd/detected");

  script_tag(name:"summary", value:"The htpasswd implementation of thttpd is affected by a buffer overflow that
  can be exploited remotely to perform code execution.

  If you are just using htpasswd to set up your own web auth files locally, there is no security implication from
  this bug. On the other hand if you are giving remote users access to htpasswd, they could conceivably use the
  buffer overrun to accomplish remote code execution as the web server user.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 2.28 or later.");

  script_xref(name:"URL", value:"http://acme.com/updates/archive/199.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.28");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
