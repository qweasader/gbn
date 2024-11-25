# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nginx:nginx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152333");
  script_version("2024-05-31T15:38:27+0000");
  script_tag(name:"last_modification", value:"2024-05-31 15:38:27 +0000 (Fri, 31 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-31 02:45:34 +0000 (Fri, 31 May 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_cve_id("CVE-2024-31079", "CVE-2024-32760", "CVE-2024-34161", "CVE-2024-35200");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nginx 1.25.0 - 1.26.0 Multiple HTTP/3 Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_nginx_consolidation.nasl");
  script_mandatory_keys("nginx/detected");

  script_tag(name:"summary", value:"Nginx is prone to multiple HTTP/3 Vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-31079: Stack overflow and use-after-free in HTTP/3

  - CVE-2024-32760: Buffer overwrite in HTTP/3

  - CVE-2024-34161: Memory disclosure in HTTP/3

  - CVE-2024-35200: NULL pointer dereference in HTTP/3");

  script_tag(name:"affected", value:"Nginx versions 1.25.0 through 1.26.0.");

  script_tag(name:"solution", value:"Update to version 1.26.1 or later.");

  script_xref(name:"URL", value:"https://nginx.org/en/security_advisories.html");
  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K000139611");
  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K000139609");
  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K000139627");
  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K000139612");

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

if (version_in_range(version: version, test_version: "1.25.0", test_version2: "1.26.0")) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.26.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
