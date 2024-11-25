# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ntp:ntp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146237");
  script_version("2024-02-20T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2021-07-07 08:48:39 +0000 (Wed, 07 Jul 2021)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2005-2496");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NTPd <= 4.2.0 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("ntp_open.nasl", "gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_tag(name:"summary", value:"NTPd is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The xntpd ntp (ntpd) daemon, when run with the -u option and
  using a string to specify the group, uses the group ID of the user instead of the group, which
  causes xntpd to run with different privileges than intended.");

  script_tag(name:"solution", value:"See the referenced vendor advisory.");

  script_xref(name:"URL", value:"https://bugs.ntp.org/show_bug.cgi?id=392");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
proto = infos["proto"];

if (version_is_less_equal(version: version, test_version: "4.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory", install_path: location);
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

exit(99);
