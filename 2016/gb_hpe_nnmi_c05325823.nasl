# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:network_node_manager_i";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106401");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-11-18 10:07:02 +0700 (Fri, 18 Nov 2016)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-05 16:16:00 +0000 (Fri, 05 Oct 2018)");

  script_cve_id("CVE-2016-4398", "CVE-2016-4399", "CVE-2016-4400");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HPE Network Node Manager i (NNMi) Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_hpe_nnmi_detect.nasl");
  script_mandatory_keys("hpe/nnmi/installed");

  script_tag(name:"summary", value:"HPE Network Node Manager i is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"HPE Network Node Manager i is prone to multiple vulnerabilities:

  - Remote Code Execution (CVE-2016-4398)

  - Cross Site Scripting (CVE-2016-4399, CVE-2016-4400)");

  script_tag(name:"impact", value:"An authenticated user may execute arbitrary code.");

  script_tag(name:"affected", value:"HPE Network Node Manager i (NNMi) Software 10.00, 10.01 (patch1),
10.01 (patch 2), 10.10");

  script_tag(name:"solution", value:"See the referenced security bulletin for a solution.");

  script_xref(name:"URL", value:"http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05325823");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "10.00", test_version2: "10.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
