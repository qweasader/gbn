# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:commons_io";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153371");
  script_version("2024-11-06T05:05:44+0000");
  script_tag(name:"last_modification", value:"2024-11-06 05:05:44 +0000 (Wed, 06 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-11-05 09:00:24 +0000 (Tue, 05 Nov 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2024-47554");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Commons IO 2.0.x < 2.14.0 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_apache_commons_consolidation.nasl");
  script_mandatory_keys("apache/commons/io/detected");

  script_tag(name:"summary", value:"The Apache Commons IO library is prone to a denial of service
  (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The org.apache.commons.io.input.XmlStreamReader class may
  excessively consume CPU resources when processing maliciously crafted input.");

  script_tag(name:"affected", value:"Apache Commons IO version 2.0.x prior to 2.14.0.");

  script_tag(name:"solution", value:"Update to version 2.14.0 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/6ozr91rr9cj5lm0zyhv30bsp317hk5z1");

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

if (version_in_range_exclusive(version: version, test_version_lo: "2.0", test_version_up: "2.14.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.14.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
