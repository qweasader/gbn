# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114277");
  script_version("2024-01-16T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-01-16 05:05:27 +0000 (Tue, 16 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-15 13:00:32 +0000 (Mon, 15 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2023-6237");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("OpenSSL DoS Vulnerability (20240115) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"OpenSSL is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Applications that use the function EVP_PKEY_public_check() to
  check RSA public keys may experience long delays.");

  script_tag(name:"impact", value:"Where the key that is being checked has been obtained from an
  untrusted source this may lead to a Denial of Service");

  script_tag(name:"affected", value:"OpenSSL versions 3.0, 3.1 and 3.2.");

  script_tag(name:"solution", value:"No known solution is available as of 15th January, 2024.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20240115.txt");

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
