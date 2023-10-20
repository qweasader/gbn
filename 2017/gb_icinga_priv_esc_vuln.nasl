# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:icinga:icinga";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140595");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-12-12 10:33:48 +0700 (Tue, 12 Dec 2017)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-27 02:15:00 +0000 (Mon, 27 Jul 2020)");

  script_cve_id("CVE-2017-16882");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Icinga Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("sw_icinga_detect.nasl");
  script_mandatory_keys("icinga/installed");

  script_tag(name:"summary", value:"Icinga is prone to a local privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Icinga Core through 1.14.0 initially executes bin/icinga as root but
supports configuration options in which this file is owned by a non-root account (and similarly can have
etc/icinga.cfg owned by a non-root account), which allows local users to gain privileges by leveraging access to
this non-root account.");

  script_tag(name:"affected", value:"Icinga 1.14.0 and prior.");

  script_tag(name:"solution", value:"Update to version 1.14.1 or later.");

  script_xref(name:"URL", value:"https://github.com/Icinga/icinga-core/issues/1601");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "1.14.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.14.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
