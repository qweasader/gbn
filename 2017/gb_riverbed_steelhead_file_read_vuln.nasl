# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:riverbed:steelhead";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106846");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-06-06 08:53:41 +0700 (Tue, 06 Jun 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Riverbed SteelHead Arbitrary File Read Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_riverbed_steelhead_ssh_detect.nasl", "gb_riverbed_steelhead_http_detect.nasl");
  script_mandatory_keys("riverbed/steelhead/detected");

  script_tag(name:"summary", value:"Riverbed SteelHead VCX is prone to an authenticated arbitrary file read
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Riverbed Steelhead VCX 9.6.0a");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42101/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

model = get_kb_item("riverbed/steelhead/model");

if (!model || model !~ "^VCX")
  exit(0);

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version == "9.6.0a") {
  report = report_fixed_ver(installed_version: version, fixed_version: "WillNotFix");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
