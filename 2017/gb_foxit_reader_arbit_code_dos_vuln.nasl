# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112056");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2017-14694", "CVE-2017-15770", "CVE-2017-15771");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"creation_date", value:"2017-10-26 11:18:43 +0530 (Thu, 26 Oct 2017)");
  script_name("Foxit Reader Arbitrary Code Execution and Denial of Service Vulnerabilities - Windows");

  script_tag(name:"summary", value:"Foxit Reader is prone to a code execution and denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Foxit Reader allows attackers to execute arbitrary code or
      cause a denial of service via a crafted .pdf file, related to 'Data from Faulting Address controls Code Flow starting at
      tiptsf!CPenInputPanel::FinalRelease+0x000000000000002f'.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attackers to execute arbitrary code or crash the application via a buffer
  overflow.");

  script_tag(name:"affected", value:"Foxit Reader version 8.3.2.25013 and earlier on Windows");
  script_tag(name:"solution", value:"Update to Foxit Reader 9.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/wlinzi/security_advisories/tree/master/CVE-2017-14694");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101009");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101540");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101549");
  script_xref(name:"URL", value:"https://github.com/wlinzi/security_advisories/tree/master/CVE-2017-15771");
  script_xref(name:"URL", value:"https://github.com/wlinzi/security_advisories/tree/master/CVE-2017-15770");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less_equal(version:ver, test_version:"8.3.2.25013"))
{
  report = report_fixed_ver(installed_version:ver, fixed_version:"9.0");
  security_message(data:report);
  exit(0);
}
