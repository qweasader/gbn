# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:edge_chromium_based";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832092");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2023-2941", "CVE-2023-2940", "CVE-2023-2939", "CVE-2023-2938", "CVE-2023-2937",
                "CVE-2023-2936", "CVE-2023-2934", "CVE-2023-2933", "CVE-2023-2932", "CVE-2023-2931",
                "CVE-2023-2930", "CVE-2023-2929", "CVE-2023-33143", "CVE-2023-29345");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-02 03:10:00 +0000 (Fri, 02 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-15 16:18:50 +0530 (Thu, 15 Jun 2023)");
  script_name("Microsoft Edge (Chromium-Based) Multiple Vulnerabilities-01 (Jun 2023)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Edge (Chromium-Based) updates.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An inappropriate implementation in Downloads.

  - An inappropriate implementation in Extensions API.

  - An insufficient data validation in Installer.

  - An inappropriate implementation in Picture In Picture.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code, gain access to sensitive information,
  bypass security restrictions, cause denial of service and may have other
  impacts on affected system.");

  script_tag(name:"affected", value:"Microsoft Edge (Chromium-Based) prior to version 114.0.1823.37.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-2940");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_edge_chromium_based_detect_win.nasl");
  script_mandatory_keys("microsoft_edge_chromium/installed", "microsoft_edge_chromium/ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"114.0.1823.37"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"114.0.1823.37", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
