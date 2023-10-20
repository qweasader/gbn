# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805406");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2011-1798", "CVE-2011-1796", "CVE-2011-1795", "CVE-2011-1794",
                "CVE-2011-1793");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-01-02 14:21:05 +0530 (Fri, 02 Jan 2015)");
  script_name("Google Chrome Multiple Vulnerabilities - Jan15 (Windows)");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Use-after-free vulnerability in the FrameView::calculateScrollbarModesForLayout
  function in page/FrameView.cpp script within WebCore in WebKit.

  - Integer underflow in the HTMLFormElement::removeFormElement function in
  html/HTMLFormElement.cpp script within WebCore in WebKit.

  - Integer overflow in the FilterEffect::copyImageBytes function in
  platform/graphics/filters/FilterEffect.cpp script within WebCore in WebKit.

  - Integer overflow in the FilterEffect.

  - Two unspecified errors in rendering/svg/RenderSVGText.cpp script within
  WebCore in WebKit.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (application crash) or possibly have
  unspecified other impacts.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  11.0.696.65 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  11.0.696.65 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://trac.webkit.org/changeset/85406");
  script_xref(name:"URL", value:"https://code.google.com/p/chromium/issues/detail?id=67923");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/ubuntu/+source/chromium-browser/+bug/778822");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!chromeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"11.0.696.65"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"11.0.696.65");
  security_message(port: 0, data: report);
  exit(0);
}
