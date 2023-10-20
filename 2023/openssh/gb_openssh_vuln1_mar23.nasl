# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104634");
  script_version("2023-10-13T05:06:10+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-03-16 07:20:41 +0000 (Thu, 16 Mar 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-23 14:07:00 +0000 (Thu, 23 Mar 2023)");

  script_cve_id("CVE-2023-28531");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenBSD OpenSSH 8.9 - 9.2 Unspecified Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_tag(name:"summary", value:"OpenBSD OpenSSH is prone to an unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"ssh-add(1): when adding smartcard keys to ssh-agent(1) with the
  per-hop destination constraints (ssh-add -h ...) added in OpenSSH 8.9, a logic error prevented the
  constraints from being communicated to the agent. This resulted in the keys being added without
  constraints. The common cases of non-smartcard keys and keys without destination constraints are
  unaffected. This problem was reported by Luci Stanescu.");

  script_tag(name:"affected", value:"OpenBSD OpenSSH versions starting from 8.9 and prior to 9.3.");

  script_tag(name:"solution", value:"Update to version 9.3 or later.");

  script_xref(name:"URL", value:"https://www.openssh.com/releasenotes.html#9.3");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/03/15/8");

  exit(0);
}
include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "8.9", test_version_up: "9.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
