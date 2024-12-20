# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ui:unifi_protect";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144232");
  script_version("2024-11-22T15:40:47+0000");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2020-07-14 08:47:29 +0000 (Tue, 14 Jul 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-09 16:33:00 +0000 (Thu, 09 Jul 2020)");

  script_cve_id("CVE-2020-8188");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("UniFi Protect < 1.13.3, 1.14.0 < 1.14.10 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_ui_unifi_protect_ubnt_detect.nasl");
  script_mandatory_keys("ui/unifi_protect/detected");

  script_tag(name:"summary", value:"UniFi Protect is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"View only users can run certain custom commands which allows
  them to assign themselves unauthorized roles and escalate their privileges.");

  script_tag(name:"affected", value:"UniFi Protect version 1.13.2 and prior and 1.14.0 through
  1.14.9.");

  script_tag(name:"solution", value:"Update to version 1.13.3, 1.14.10 or later.");

  script_xref(name:"URL", value:"https://community.ui.com/releases/Security-advisory-bulletin-012-012/1bba9134-f888-4010-81c0-b0dd53b9bda4");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "1.13.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.13.3");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.14.0", test_version2: "1.14.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.14.10");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
