# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nlnetlabs:unbound";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152852");
  script_version("2024-10-11T05:05:54+0000");
  script_tag(name:"last_modification", value:"2024-10-11 05:05:54 +0000 (Fri, 11 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-08-13 02:36:43 +0000 (Tue, 13 Aug 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2024-43167");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Unbound DNS Resolver <= 1.20.0 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("unbound_version.nasl");
  script_mandatory_keys("unbound/installed");

  script_tag(name:"summary", value:"Unbound DNS Resolver is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A NULL pointer dereference exists in the ub_ctx_set_fwd
  function.");

  script_tag(name:"affected", value:"Unbound DNS Resolver version 1.20.0 and prior.");

  # nb: As there is no advisory for / .txt file for CVE-2024-43167 the fixed version has been
  # determined from the release-1.21.0 link below which contains the link to the PR included below:
  #
  # > Merge #1073: fix null pointer dereference issue in function ub_ctx_set_fwd.
  script_tag(name:"solution", value:"Update to version 1.21.0 or later.");

  script_xref(name:"URL", value:"https://github.com/NLnetLabs/unbound/issues/1072");
  script_xref(name:"URL", value:"https://github.com/NLnetLabs/unbound/pull/1073");
  script_xref(name:"URL", value:"https://github.com/NLnetLabs/unbound/releases/tag/release-1.21.0");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
proto = infos["proto"];

if (version_is_less_equal(version: version, test_version: "1.20.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.21.0");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

exit(99);
