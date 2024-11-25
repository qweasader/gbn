# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_dc_classic";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814232");
  script_version("2024-02-12T05:05:32+0000");
  script_cve_id("CVE-2018-15955", "CVE-2018-15954", "CVE-2018-15952", "CVE-2018-15945",
                "CVE-2018-15944", "CVE-2018-15941", "CVE-2018-15940", "CVE-2018-15939",
                "CVE-2018-15938", "CVE-2018-15936", "CVE-2018-15935", "CVE-2018-15934",
                "CVE-2018-15933", "CVE-2018-15929", "CVE-2018-15928", "CVE-2018-12868",
                "CVE-2018-12865", "CVE-2018-12864", "CVE-2018-12862", "CVE-2018-12861",
                "CVE-2018-12860", "CVE-2018-12759", "CVE-2018-15956", "CVE-2018-15953",
                "CVE-2018-15950", "CVE-2018-15949", "CVE-2018-15948", "CVE-2018-15947",
                "CVE-2018-15946", "CVE-2018-15943", "CVE-2018-15942", "CVE-2018-15932",
                "CVE-2018-15927", "CVE-2018-15926", "CVE-2018-15925", "CVE-2018-15923",
                "CVE-2018-15922", "CVE-2018-12880", "CVE-2018-12879", "CVE-2018-12878",
                "CVE-2018-12875", "CVE-2018-12874", "CVE-2018-12873", "CVE-2018-12872",
                "CVE-2018-12871", "CVE-2018-12870", "CVE-2018-12869", "CVE-2018-12867",
                "CVE-2018-12866", "CVE-2018-12859", "CVE-2018-12857", "CVE-2018-12856",
                "CVE-2018-12845", "CVE-2018-12844", "CVE-2018-12843", "CVE-2018-12839",
                "CVE-2018-12834", "CVE-2018-15968", "CVE-2018-12851", "CVE-2018-12847",
                "CVE-2018-12846", "CVE-2018-12837", "CVE-2018-12836", "CVE-2018-12833",
                "CVE-2018-12832", "CVE-2018-15924", "CVE-2018-15920", "CVE-2018-12877",
                "CVE-2018-12863", "CVE-2018-12852", "CVE-2018-12831", "CVE-2018-12769",
                "CVE-2018-12876", "CVE-2018-12858", "CVE-2018-12835", "CVE-2018-12838",
                "CVE-2018-12841", "CVE-2018-12881", "CVE-2018-12842", "CVE-2018-15951",
                "CVE-2018-12855", "CVE-2018-12853", "CVE-2018-15937", "CVE-2018-15931",
                "CVE-2018-15930", "CVE-2018-15966", "CVE-2018-19722");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-24 21:15:00 +0000 (Mon, 24 Feb 2020)");
  script_tag(name:"creation_date", value:"2018-10-03 16:53:36 +0530 (Wed, 03 Oct 2018)");
  script_name("Adobe Acrobat DC Classic 2015 Security Updates (APSB18-30) - Windows");

  script_tag(name:"summary", value:"Adobe Acrobat DC Classic 2015 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to an Out-of-bounds
  write error, an Out-of-bounds read error, a Heap Overflow error, Use After Free
  error, Type Confusion error, Stack Overflow error, Double Free error, Integer
  Overflow error, Buffer errors, Untrusted pointer dereference error and Security
  Bypass error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code execution, gain privilege escalation and gain
  access to potentially sensitive information.");

  script_tag(name:"affected", value:"Adobe Acrobat DC Classic 2015 version 2015.x
  before 2015.006.30456 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat DC Classic 2015 version
  2015.006.30456 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb18-30.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_dc_classic_detect_win.nasl");
  script_mandatory_keys("Adobe/AcrobatDC/Classic/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_in_range(version:vers, test_version:"15.0", test_version2:"15.006.30455")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"15.006.30456 (2015.006.30456)", install_path:path);
  security_message(data:report);
  exit(0);
}
