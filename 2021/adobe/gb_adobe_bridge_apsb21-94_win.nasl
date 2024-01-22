# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:bridge_cc";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818846");
  script_version("2023-11-24T05:05:36+0000");
  # nb: A few of the CVEs used below are not mentioned on APSB21-94 but their Mitre CVE entries are
  # actually linking to that advisory. Seems Adobe had missed to add the CVEs to this advisory in
  # the past but these are still added here.
  script_cve_id("CVE-2021-40750", "CVE-2021-42533", "CVE-2021-42719", "CVE-2021-42720",
                "CVE-2021-42722", "CVE-2021-42724", "CVE-2021-42728", "CVE-2021-42729",
                "CVE-2021-42730", "CVE-2021-42721", "CVE-2021-42723", "CVE-2021-42726",
                "CVE-2021-42725", "CVE-2021-42727");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-24 05:05:36 +0000 (Fri, 24 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-17 18:33:00 +0000 (Wed, 17 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-10-28 19:41:37 +0530 (Thu, 28 Oct 2021)");
  script_name("Adobe Bridge Multiple Vulnerabilities (APSB21-94) - Windows");

  script_tag(name:"summary", value:"Adobe Bridge is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - NULL Pointer Dereference error.

  - Double Free error.

  - Multiple Out-of-bounds Read errors.

  - A Buffer Overflow error.

  - Access of Memory Location After End of Buffer.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution and memory leak on the system.");

  script_tag(name:"affected", value:"Adobe Bridge 11.1.1 and earlier versions on
  Windows.");

  script_tag(name:"solution", value:"Update to version 11.1.2, 12.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/bridge/apsb21-94.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_bridge_cc_detect.nasl");
  script_mandatory_keys("Adobe/Bridge/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"11.1.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"11.1.2 or 12.0", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
