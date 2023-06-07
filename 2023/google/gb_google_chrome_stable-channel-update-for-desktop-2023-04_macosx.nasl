# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832105");
  script_version("2023-04-13T10:19:10+0000");
  script_cve_id("CVE-2023-1810", "CVE-2023-1811", "CVE-2023-1812", "CVE-2023-1813",
                "CVE-2023-1814", "CVE-2023-1815", "CVE-2023-1816", "CVE-2023-1817",
                "CVE-2023-1818", "CVE-2023-1819", "CVE-2023-1820", "CVE-2023-1821",
                "CVE-2023-1822", "CVE-2023-1823");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-04-13 10:19:10 +0000 (Thu, 13 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-07 15:14:50 +0530 (Fri, 07 Apr 2023)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop-2023-04)-MAC OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Heap buffer overflow in Visuals.

  - Use after free in Frames.

  - Out of bounds memory access in DOM Bindings.

  - Inappropriate implementation in Extensions.

  - Insufficient validation of untrusted input in Safe Browsing.

  - Use after free in Networking APIs.

  - Incorrect security UI in Picture In Picture.

  - Insufficient policy enforcement in Intents.

  - Use after free in Vulkan.

  - Out of bounds read in Accessibility.

  - Heap buffer overflow in Browser History.

  - Inappropriate implementation in WebShare.

  - Incorrect security UI in Navigation.

  - Inappropriate implementation in FedCM");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to run arbitrary code, bypass security restrictions, conduct spoofing and
  cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to 112.0.5615.49 on MAC OS X");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 112.0.5615.49 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/04/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"112.0.5615.49"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"112.0.5615.49", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
