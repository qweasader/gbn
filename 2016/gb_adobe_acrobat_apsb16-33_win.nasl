# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809448");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-1089", "CVE-2016-1091", "CVE-2016-6939", "CVE-2016-6940",
                "CVE-2016-6941", "CVE-2016-6942", "CVE-2016-6943", "CVE-2016-6944",
                "CVE-2016-6945", "CVE-2016-6946", "CVE-2016-6947", "CVE-2016-6948",
                "CVE-2016-6949", "CVE-2016-6950", "CVE-2016-6951", "CVE-2016-6952",
                "CVE-2016-6953", "CVE-2016-6954", "CVE-2016-6955", "CVE-2016-6956",
                "CVE-2016-6957", "CVE-2016-6958", "CVE-2016-6959", "CVE-2016-6960",
                "CVE-2016-6961", "CVE-2016-6962", "CVE-2016-6963", "CVE-2016-6964",
                "CVE-2016-6965", "CVE-2016-6966", "CVE-2016-6967", "CVE-2016-6968",
                "CVE-2016-6969", "CVE-2016-6970", "CVE-2016-6971", "CVE-2016-6972",
                "CVE-2016-6973", "CVE-2016-6974", "CVE-2016-6975", "CVE-2016-6976",
                "CVE-2016-6977", "CVE-2016-6978", "CVE-2016-6979", "CVE-2016-6988",
                "CVE-2016-6993", "CVE-2016-6994", "CVE-2016-6995", "CVE-2016-6996",
                "CVE-2016-6997", "CVE-2016-6998", "CVE-2016-6999", "CVE-2016-7000",
                "CVE-2016-7001", "CVE-2016-7002", "CVE-2016-7003", "CVE-2016-7004",
                "CVE-2016-7005", "CVE-2016-7006", "CVE-2016-7007", "CVE-2016-7008",
                "CVE-2016-7009", "CVE-2016-7010", "CVE-2016-7011", "CVE-2016-7012",
                "CVE-2016-7013", "CVE-2016-7014", "CVE-2016-7015", "CVE-2016-7016",
                "CVE-2016-7017", "CVE-2016-7018", "CVE-2016-7019", "CVE-2016-7854",
                "CVE-2016-7853", "CVE-2016-7852");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-30 01:29:00 +0000 (Sun, 30 Jul 2017)");
  script_tag(name:"creation_date", value:"2016-10-13 12:55:40 +0530 (Thu, 13 Oct 2016)");
  script_name("Adobe Acrobat Security Updates(apsb16-33)-Windows");

  script_tag(name:"summary", value:"Adobe Acrobat is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An use-after-free vulnerabilities.

  - The heap buffer overflow vulnerabilities.

  - The memory corruption vulnerabilities.

  - An integer overflow vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers lead to code execution and
  to bypass restrictions on Javascript API execution.");

  script_tag(name:"affected", value:"Adobe Acrobat version 11.x before 11.0.18 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat version
  11.0.18 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb16-33.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Acrobat/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:readerVer, test_version:"11.0", test_version2:"11.0.17"))
{
  report = report_fixed_ver(installed_version:readerVer, fixed_version:"11.0.18");
  security_message(data:report);
  exit(0);
}
