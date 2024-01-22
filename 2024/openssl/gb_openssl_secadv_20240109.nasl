# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114253");
  script_version("2024-01-10T05:05:17+0000");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-09 17:13:14 +0000 (Tue, 09 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2023-6129");

  # nb: Only a single VT as only PowerPC systems are affected
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("OpenSSL Vector Register Corruption Vulnerability (20240109)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl");
  script_mandatory_keys("openssl/detected");

  script_tag(name:"summary", value:"OpenSSL is prone to a vector register corruption
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The POLY1305 MAC (message authentication code) implementation
  contains a bug that might corrupt the internal state of applications running on PowerPC CPU based
  platforms if the CPU provides vector instructions.");

  script_tag(name:"impact", value:"If an attacker can influence whether the POLY1305 MAC algorithm
  is used, the application state might be corrupted with various application dependent
  consequences.");

  script_tag(name:"affected", value:"OpenSSL versions 3.0, 3.1 and 3.2 on PowerPC CPU based
  platforms if the CPU provides vector instructions.");

  script_tag(name:"solution", value:"No known solution is available as of 09th January, 2024.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20240109.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version =~ "^3\.[0-2]") {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99); # nb: We can use exit(99); here since other versions like 0.9.8, 1.0.2 and 1.1.1 are not affected
