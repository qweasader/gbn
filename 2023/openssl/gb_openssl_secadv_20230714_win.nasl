# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104839");
  script_version("2023-10-13T05:06:10+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-07-17 06:30:34 +0000 (Mon, 17 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-27 13:02:00 +0000 (Thu, 27 Jul 2023)");

  script_cve_id("CVE-2023-2975");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("OpenSSL Information Disclosure Vulnerability (20230714) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"OpenSSL is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The AES-SIV cipher implementation contains a bug that causes it
  to ignore empty associated data entries which are unauthenticated as a consequence.");

  script_tag(name:"impact", value:"Applications that use the AES-SIV algorithm and want to
  authenticate empty data entries as associated data can be misled by removing, adding or reordering
  such empty entries as these are ignored by the OpenSSL implementation. The vendor is currently
  unaware of any such applications.");

  script_tag(name:"affected", value:"OpenSSL version 3.0 and 3.1.");

  script_tag(name:"solution", value:"No known solution is available as of 19th July, 2023.
  Information regarding this issue will be updated once solution details are available.

  Vendor info: Due to the low severity of this issue we are not issuing new releases of OpenSSL at
  this time. The fix will be included in the next releases when they become available. The fix is
  also available in commit 6a83f0c9 (for 3.1) and commit 00e2f5ee (for 3.0) in the OpenSSL git
  repository.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20230714.txt");

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

if (version_in_range(version: version, test_version: "3.0.0", test_version2: "3.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.1.0", test_version2: "3.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99); # nb: We can use exit(99); here since other versions like 0.9.8 are not affected
