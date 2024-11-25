# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150775");
  script_version("2024-07-31T05:05:34+0000");
  script_tag(name:"last_modification", value:"2024-07-31 05:05:34 +0000 (Wed, 31 Jul 2024)");
  script_tag(name:"creation_date", value:"2023-07-27 03:28:59 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-31 01:27:00 +0000 (Fri, 31 Mar 2023)");

  script_cve_id("CVE-2023-24094");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("MikroTik RouterOS <= 6.40.5 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An issue in the bridge2 component of MikroTik RouterOS allows
  attackers to cause a Denial of Service (DoS) via crafted packets.");

  script_tag(name:"affected", value:"MikroTik RouterOS version 6.40.5 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_xref(name:"URL", value:"https://github.com/ZYen12138/RouterOS/blob/main/CVE-2023-24094.md");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "6.40.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
