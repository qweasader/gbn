# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:bridge_cc";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817957");
  script_version("2024-02-12T05:05:32+0000");
  script_cve_id("CVE-2021-21065", "CVE-2021-21066");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-26 19:14:00 +0000 (Fri, 26 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-26 11:20:57 +0530 (Fri, 26 Feb 2021)");
  script_name("Adobe Bridge Multiple Code Execution Vulnerabilities (APSB21-07) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Bridge is prone to multiple vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  out-of-bounds write errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code on the system.");

  script_tag(name:"affected", value:"Adobe Bridge 11.0 and earlier versions on
  Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Bridge 11.0.1 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/bridge/apsb21-07.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_bridge_cc_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Bridge/CC/MacOSX/Version");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"11.0.1"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"11.0.1", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
