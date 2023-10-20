# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149922");
  script_version("2023-10-13T05:06:10+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-07-12 04:27:11 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-20 12:56:00 +0000 (Thu, 20 Jul 2023)");

  script_cve_id("CVE-2023-36824");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis 7.0.0 < 7.0.12 Heap Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Redis is prone to a heap overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Extracting key names from a command and a list of arguments
  may, in some cases, trigger a heap overflow and result in reading random heap memory, heap
  corruption and potentially remote code execution. Several scenarios that may lead to this result:

  - Authenticated users executing a specially crafted COMMAND GETKEYS or COMMAND GETKEYSANDFLAGS.

  - Authenticated users who were set with ACL rules that match key names, executing a specially
  crafted command that refers to a variadic list of key names.");

  script_tag(name:"affected", value:"Redis version 7.0.0 through 7.0.11.");

  script_tag(name:"solution", value:"Update to version 7.0.12 or later.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-4cfx-h9gq-xpx3");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.0.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.12");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
