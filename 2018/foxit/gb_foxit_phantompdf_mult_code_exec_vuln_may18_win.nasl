# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:phantompdf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812896");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2018-5674", "CVE-2018-5677", "CVE-2018-5676", "CVE-2018-5675",
                "CVE-2018-5678", "CVE-2018-5680", "CVE-2018-5679", "CVE-2018-7407",
                "CVE-2018-7406");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-08 17:11:00 +0000 (Fri, 08 Jun 2018)");
  script_tag(name:"creation_date", value:"2018-05-25 13:43:57 +0530 (Fri, 25 May 2018)");
  script_name("Foxit PhantomPDF Multiple Code Execution Vulnerabilities - May18 (Windows)");

  script_tag(name:"summary", value:"Foxit PhantomPDF is prone to multiple code execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Lack of proper validation of user-supplied data.

  - Foxit PhantomPDF unable to sanitize itself from crafted data in the PDF
    file.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code.");

  script_tag(name:"affected", value:"Foxit PhantomPDF versions before 9.1 on
  windows.");

  script_tag(name:"solution", value:"Upgrade to Foxit PhantomPDF version 9.1
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php#content-2018");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_phantom_reader_detect.nasl");
  script_mandatory_keys("foxit/phantompdf/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
pdfVer = infos['version'];
pdfPath = infos['location'];

if(version_is_less(version:pdfVer, test_version:"9.1"))
{
  report = report_fixed_ver(installed_version:pdfVer, fixed_version:"9.1", install_path:pdfPath);
  security_message(data:report);
  exit(0);
}
exit(0);
