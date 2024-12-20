# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818874");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2021-4052", "CVE-2021-4053", "CVE-2021-4079", "CVE-2021-4054",
                "CVE-2021-4078", "CVE-2021-4055", "CVE-2021-4056", "CVE-2021-4057",
                "CVE-2021-4058", "CVE-2021-4059", "CVE-2021-4061", "CVE-2021-4062",
                "CVE-2021-4063", "CVE-2021-4064", "CVE-2021-4065", "CVE-2021-4066",
                "CVE-2021-4067", "CVE-2021-4068");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-28 20:33:00 +0000 (Tue, 28 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-10 17:33:09 +0530 (Fri, 10 Dec 2021)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop-2021-02) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple use after free errors.

  - Multiple type confusion errors.

  - Multiple heap buffer overflow errors.

  - An out of bounds write error.

  - An incorrect security UI in autofill.

  - An integer underflow in ANGLE.

  - An insufficient data validation.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  obtain sensitive information, bypass security restrictions, execute arbitrary code
  and cause denial of service condition.");

  script_tag(name:"affected", value:"Google Chrome version prior to 96.0.4664.93
  on Linux");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 96.0.4664.93
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2021/12/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
chr_ver = infos['version'];
chr_path = infos['location'];

if(version_is_less(version:chr_ver, test_version:"96.0.4664.93"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"96.0.4664.93", install_path:chr_path);
  security_message(data:report);
  exit(0);
}
exit(99);
