# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815063");
  script_version("2024-02-12T05:05:32+0000");
  script_cve_id("CVE-2019-7140", "CVE-2019-7141", "CVE-2019-7142", "CVE-2019-7143",
                "CVE-2019-7144", "CVE-2019-7145", "CVE-2019-7758", "CVE-2019-7759",
                "CVE-2019-7760", "CVE-2019-7761", "CVE-2019-7762", "CVE-2019-7763",
                "CVE-2019-7764", "CVE-2019-7765", "CVE-2019-7766", "CVE-2019-7767",
                "CVE-2019-7768", "CVE-2019-7769", "CVE-2019-7770", "CVE-2019-7771",
                "CVE-2019-7772", "CVE-2019-7773", "CVE-2019-7774", "CVE-2019-7775",
                "CVE-2019-7776", "CVE-2019-7777", "CVE-2019-7778", "CVE-2019-7779",
                "CVE-2019-7780", "CVE-2019-7781", "CVE-2019-7782", "CVE-2019-7783",
                "CVE-2019-7784", "CVE-2019-7785", "CVE-2019-7786", "CVE-2019-7787",
                "CVE-2019-7788", "CVE-2019-7789", "CVE-2019-7790", "CVE-2019-7791",
                "CVE-2019-7792", "CVE-2019-7793", "CVE-2019-7794", "CVE-2019-7795",
                "CVE-2019-7796", "CVE-2019-7797", "CVE-2019-7798", "CVE-2019-7799",
                "CVE-2019-7800", "CVE-2019-7801", "CVE-2019-7802", "CVE-2019-7803",
                "CVE-2019-7804", "CVE-2019-7805", "CVE-2019-7806", "CVE-2019-7807",
                "CVE-2019-7808", "CVE-2019-7809", "CVE-2019-7810", "CVE-2019-7811",
                "CVE-2019-7812", "CVE-2019-7813", "CVE-2019-7814", "CVE-2019-7817",
                "CVE-2019-7818", "CVE-2019-7820", "CVE-2019-7821", "CVE-2019-7822",
                "CVE-2019-7823", "CVE-2019-7824", "CVE-2019-7825", "CVE-2019-7826",
                "CVE-2019-7827", "CVE-2019-7828", "CVE-2019-7829", "CVE-2019-7830",
                "CVE-2019-7831", "CVE-2019-7832", "CVE-2019-7833", "CVE-2019-7834",
                "CVE-2019-7835", "CVE-2019-7836", "CVE-2019-7841");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-21 16:20:00 +0000 (Wed, 21 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-05-16 11:08:46 +0530 (Thu, 16 May 2019)");
  script_name("Adobe Acrobat 2017 Security Updates (APSB19-18) - Windows");

  script_tag(name:"summary", value:"Adobe Acrobat 2017 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple out-of-bounds read errors.

  - Multiple out-of-bounds write errors.

  - A type confusion error.

  - Multiple use after free errors.

  - Multiple heap overflow errors.

  - A buffer error.

  - A double free error.

  - A security bypass error.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain access to sensitive information and run arbitrary code in context of
  current user.");

  script_tag(name:"affected", value:"Adobe Acrobat versions 2017.011.30140 and
  earlier on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat 2017 version
  2017.011.30142 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb19-18.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Acrobat/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos['version'];
path = infos['location'];

## 2017.011.30140 == 17.011.30140
if(version_in_range(version:vers, test_version:"17.0", test_version2:"17.011.30140")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"17.011.30142 (2017.011.30142)", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
