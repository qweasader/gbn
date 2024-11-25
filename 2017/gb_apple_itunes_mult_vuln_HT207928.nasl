# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811535");
  script_version("2024-02-16T14:37:06+0000");
  script_cve_id("CVE-2017-7053", "CVE-2017-7010", "CVE-2017-7013", "CVE-2017-7018",
                "CVE-2017-7020", "CVE-2017-7030", "CVE-2017-7034", "CVE-2017-7037",
                "CVE-2017-7039", "CVE-2017-7040", "CVE-2017-7041", "CVE-2017-7042",
                "CVE-2017-7043", "CVE-2017-7046", "CVE-2017-7048", "CVE-2017-7052",
                "CVE-2017-7055", "CVE-2017-7056", "CVE-2017-7061", "CVE-2017-7049",
                "CVE-2017-7064", "CVE-2017-7019", "CVE-2017-7012");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 14:37:06 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-07-20 11:40:40 +0530 (Thu, 20 Jul 2017)");
  script_name("Apple iTunes Multiple Vulnerabilities (HT207928) - Windows");

  script_tag(name:"summary", value:"Apple iTunes is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple memory corruption issues in WebKit component.

  - A memory initialization issue in WebKit component.

  - An out-of-bounds read  error in libxml2 component.

  - An access issue.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code and disclose sensitive information.");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.6.2 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apple iTunes 12.6.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207928");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99884");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99889");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99879");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99885");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99890");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

# vulnerable versions, 12.6.2 = 12.6.2.20
if(version_is_less(version:vers, test_version:"12.6.2.20")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"12.6.2", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
