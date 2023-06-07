# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104512");
  script_version("2023-03-24T10:19:42+0000");
  script_tag(name:"last_modification", value:"2023-03-24 10:19:42 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-02-03 13:51:53 +0000 (Fri, 03 Feb 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenBSD OpenSSH < 9.2 Unspecified Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_tag(name:"summary", value:"OpenBSD OpenSSH is prone to an unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If the CanonicalizeHostname and CanonicalizePermittedCNAMEs
  options were enabled, and the system/libc resolver did not check that names in DNS responses were
  valid, then use of these options could allow an attacker with control of DNS to include invalid
  characters (possibly including wildcards) in names added to known_hosts files when they were
  updated. These names would still have to match the CanonicalizePermittedCNAMEs allow-list, so
  practical exploitation appears unlikely.");

  script_tag(name:"affected", value:"OpenBSD OpenSSH prior to version 9.2.");

  script_tag(name:"solution", value:"Update to version 9.2 or later.");

  script_xref(name:"URL", value:"https://www.openssh.com/releasenotes.html#9.2");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/02/02/3");

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

if (version_is_less(version: version, test_version: "9.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
