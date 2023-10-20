# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810524");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-5007", "CVE-2017-5006", "CVE-2017-5008", "CVE-2017-5010",
                "CVE-2017-5011", "CVE-2017-5009", "CVE-2017-5012", "CVE-2017-5013",
                "CVE-2017-5014", "CVE-2017-5015", "CVE-2017-5019", "CVE-2017-5016",
                "CVE-2017-5017", "CVE-2017-5018", "CVE-2017-5020", "CVE-2017-5021",
                "CVE-2017-5022", "CVE-2017-5023", "CVE-2017-5024", "CVE-2017-5025",
                "CVE-2017-5026", "CVE-2017-5028");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"creation_date", value:"2017-01-27 16:45:20 +0530 (Fri, 27 Jan 2017)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop-2017-01)-Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple universal XSS errors in Blink component, chrome://apps and
    chrome://downloads.

  - An improper access restriction for files in Devtools.

  - An out of bounds memory access error in WebRTC.

  - A heap overflow error in V8.

  - An address spoofing error in Omnibox.

  - A heap overflow error in Skia.

  - An use after free error in Renderer.

  - An UI spoofing error in Blink component.

  - An uninitialised memory access error in webm video.

  - An use after free error in Extensions.

  - The bypass of Content Security Policy in Blink.

  - A type confusion error in metrics.

  - A heap overflow error in FFmpeg.

  - The various fixes from internal audits, fuzzing and other initiatives.

  - An insufficient data validation in V8 in Google Chrome.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote attacker to bypass security, execute
  arbitrary code, cause denial of service and conduct spoofing attacks.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 56.0.2924.76 on Linux");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  56.0.2924.76 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/01/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

if(version_is_less(version:chr_ver, test_version:"56.0.2924.76"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"56.0.2924.76", install_path:chr_path);
  security_message(data:report);
  exit(0);
}
