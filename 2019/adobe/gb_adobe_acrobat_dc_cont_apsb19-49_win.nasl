# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_dc_continuous";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815806");
  script_version("2024-02-12T05:05:32+0000");
  script_cve_id("CVE-2019-8064", "CVE-2019-8160", "CVE-2019-8161", "CVE-2019-8162",
                "CVE-2019-8163", "CVE-2019-8164", "CVE-2019-8165", "CVE-2019-8166",
                "CVE-2019-8167", "CVE-2019-8168", "CVE-2019-8169", "CVE-2019-8170",
                "CVE-2019-8171", "CVE-2019-8172", "CVE-2019-8173", "CVE-2019-8174",
                "CVE-2019-8175", "CVE-2019-8176", "CVE-2019-8177", "CVE-2019-8178",
                "CVE-2019-8179", "CVE-2019-8180", "CVE-2019-8181", "CVE-2019-8182",
                "CVE-2019-8183", "CVE-2019-8184", "CVE-2019-8185", "CVE-2019-8186",
                "CVE-2019-8187", "CVE-2019-8188", "CVE-2019-8189", "CVE-2019-8190",
                "CVE-2019-8191", "CVE-2019-8192", "CVE-2019-8193", "CVE-2019-8194",
                "CVE-2019-8195", "CVE-2019-8196", "CVE-2019-8197", "CVE-2019-8198",
                "CVE-2019-8199", "CVE-2019-8200", "CVE-2019-8201", "CVE-2019-8202",
                "CVE-2019-8203", "CVE-2019-8204", "CVE-2019-8205", "CVE-2019-8206",
                "CVE-2019-8207", "CVE-2019-8208", "CVE-2019-8209", "CVE-2019-8210",
                "CVE-2019-8211", "CVE-2019-8212", "CVE-2019-8213", "CVE-2019-8214",
                "CVE-2019-8215", "CVE-2019-8216", "CVE-2019-8217", "CVE-2019-8218",
                "CVE-2019-8219", "CVE-2019-8220", "CVE-2019-8221", "CVE-2019-8222",
                "CVE-2019-8223", "CVE-2019-8224", "CVE-2019-8225", "CVE-2019-8226");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-22 15:15:00 +0000 (Tue, 22 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-16 11:08:11 +0530 (Wed, 16 Oct 2019)");
  script_name("Adobe Acrobat DC (Continuous Track) Security Updates (APSB19-49) - Windows");

  script_tag(name:"summary", value:"Adobe Acrobat DC (Continuous Track) is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple out-of-bounds read errors.

  - Multiple out-of-bounds write errors.

  - Multiple type confusion errors.

  - Multiple use after free errors.

  - Multiple heap overflow errors.

  - A buffer overrun error.

  - A cross site scripting error.

  - A race condition error.

  - An incomplete implementation of security mechanism.

  - An untrusted pointer dereference error.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain access to sensitive information and run arbitrary code in context of
  current user.");

  script_tag(name:"affected", value:"Adobe Acrobat DC (Continuous Track)
  2019.012.20040 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat DC Continuous
  version 2019.021.20047 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb19-49.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_dc_cont_detect_win.nasl");
  script_mandatory_keys("Adobe/AcrobatDC/Continuous/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

## 2019.012.20040 == 19.012.20040
if(version_is_less_equal(version:vers, test_version:"19.012.20040")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"19.021.20047 (2019.021.20047)", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
