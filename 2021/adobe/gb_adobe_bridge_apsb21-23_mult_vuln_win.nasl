# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:bridge_cc";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818043");
  script_version("2024-02-12T05:05:32+0000");
  script_cve_id("CVE-2021-21091", "CVE-2021-21096", "CVE-2021-21093", "CVE-2021-21092",
                "CVE-2021-21094", "CVE-2021-21095");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-07 03:29:00 +0000 (Tue, 07 Nov 2023)");
  script_tag(name:"creation_date", value:"2021-04-15 17:27:48 +0530 (Thu, 15 Apr 2021)");
  script_name("Adobe Bridge Security Updates (APSB21-23) - Windows");

  script_tag(name:"summary", value:"Adobe Bridge is prone to multiple vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An out-of-bounds read error.

  - Multiple out-of-bounds write error.

  - An improper authorization error.

  - Multiple memory corruption error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code, gain privilege escalation and obtain
  sensitive information on the system.");

  script_tag(name:"affected", value:"Adobe Bridge 10.1.1 and earlier versions,
  and 11.0.1 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Bridge 10.1.2, 11.0.2 or later. Please
  see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/bridge/apsb21-23.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_bridge_cc_detect.nasl");
  script_mandatory_keys("Adobe/Bridge/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if(vers =~ "^10\.") {
  if(version_is_less(version:vers, test_version:"10.1.2")) {
    fix = "10.1.2";
  }
}

else if(vers =~ "^11\.") {
  if(version_is_less(version:vers, test_version:"11.0.2")) {
    fix = "11.0.2";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
