# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149157");
  script_version("2023-03-24T10:19:42+0000");
  script_tag(name:"last_modification", value:"2023-03-24 10:19:42 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-01-18 04:17:17 +0000 (Wed, 18 Jan 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2022-35977");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis < 6.0.17 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Redis is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Integer overflow in the Redis SETRANGE and SORT/SORT_RO
  commands can drive Redis to OOM panic.");

  script_tag(name:"affected", value:"Redis versions prior to 6.0.17.");

  script_tag(name:"solution", value:"Update to version 6.0.17 or later.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-mrcw-fhw9-fj8j");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/6.0.17");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "6.0.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.17");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
