# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:fortinet:fortiweb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105795");
  script_version("2024-11-07T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-11-07 05:05:35 +0000 (Thu, 07 Nov 2024)");
  script_tag(name:"creation_date", value:"2016-07-05 19:08:43 +0200 (Tue, 05 Jul 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:14:00 +0000 (Mon, 28 Nov 2016)");

  script_cve_id("CVE-2016-4066");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Fortinet FortiWeb CSRF Vulnerability (FG-IR-16-010)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("FortiOS Local Security Checks");
  script_dependencies("gb_fortiweb_version.nasl");
  script_mandatory_keys("fortiweb/version");

  script_tag(name:"summary", value:"Fortinet FortiWeb is prone to a cross-site request forgery
  (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The vulnerability could allow attackers to change admin
  password with crafted forms.");

  script_tag(name:"affected", value:"Fortinet FortiWeb versions prior to 5.5.3.");

  script_tag(name:"solution", value:"Update to version 5.5.3 or later.");

  script_xref(name:"URL", value:"https://www.fortiguard.com/psirt/FG-IR-16-010");
  script_xref(name:"Advisory-ID", value:"FG-IR-16-010");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "5.5.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.3");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
