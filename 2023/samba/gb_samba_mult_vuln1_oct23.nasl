# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104958");
  script_version("2023-11-16T05:05:14+0000");
  script_tag(name:"last_modification", value:"2023-11-16 05:05:14 +0000 (Thu, 16 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-10-11 10:01:35 +0000 (Wed, 11 Oct 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-14 18:20:00 +0000 (Tue, 14 Nov 2023)");

  script_cve_id("CVE-2023-4154", "CVE-2023-42669");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Samba 4.0.0 < 4.17.12, 4.18.0 < 4.18.8, 4.19.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_tag(name:"summary", value:"Samba is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-4154: Samba AD DC password exposure to privileged users and RODCs

  - CVE-2023-42669: 'rpcecho' development server allows Denial of Service via sleep() call on AD
  DC");

  script_tag(name:"affected", value:"All versions of Samba since 4.0.0.");

  script_tag(name:"solution", value:"Update to version 4.17.12, 4.18.8, 4.19.1 or later.");

  script_xref(name:"URL", value:"https://lists.samba.org/archive/samba-announce/2023/000651.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2023-4154.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2023-42669.html");

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

if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "4.17.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.17.12 / 4.18.8 / 4.19.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.18.0", test_version_up: "4.18.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.18.8 / 4.19.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.19.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.19.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
