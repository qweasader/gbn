# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:phantompdf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815265");
  script_version("2024-02-23T14:36:45+0000");
  script_cve_id("CVE-2019-14207", "CVE-2019-14211", "CVE-2019-14212", "CVE-2019-14213",
                "CVE-2019-14215");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-23 14:36:45 +0000 (Fri, 23 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-07-25 15:28:11 +0530 (Thu, 25 Jul 2019)");
  script_name("Foxit PhantomPDF < 8.3.11 Multiple Vulnerabilities (Jul 2019) - Windows");

  script_tag(name:"summary", value:"Foxit PhantomPDF is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An issue in calling the clone function due to an endless loop resulting from
    confusing relationships between a child and parent object.

  - An issue in the execution of JavaScript which results from lack of validating
    the existence of an object prior to performing operations on the object.

  - An issue in calling certain XFA JavaScript due to the use of, or access to,
    a NULL pointer without proper validation on the object.

  - Repeated release of the signature dictionary during CSG_SignatureF
    and CPDF_Document destruction could result in a crash.

  - An issue in calling xfa.event.rest XFA JavaScript due to accessing a wild pointer.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause denial of service condition.");

  script_tag(name:"affected", value:"Foxit PhantomPDF version 8.3.10.42705 and prior
  on Windows.");

  script_tag(name:"solution", value:"Update to version 8.3.11 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/pdf-editor/");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");

  script_copyright("Copyright (C) 2019 Greenbone AG");
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

if(version_is_less_equal(version:pdfVer, test_version:"8.3.10.42705"))
{
  report = report_fixed_ver(installed_version:pdfVer, fixed_version:"8.3.11", install_path:pdfPath);
  security_message(data:report);
  exit(0);
}
exit(99);
