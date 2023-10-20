# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805631");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-1251", "CVE-2015-1252", "CVE-2015-1253", "CVE-2015-1254",
                "CVE-2015-1255", "CVE-2015-1256", "CVE-2015-1257", "CVE-2015-1258",
                "CVE-2015-1259", "CVE-2015-1260", "CVE-2015-1262", "CVE-2015-1263",
                "CVE-2015-1264", "CVE-2015-1265", "CVE-2015-3910");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-05-27 09:42:43 +0530 (Wed, 27 May 2015)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Google Chrome Multiple Vulnerabilities - 02 - May15 (Windows)");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple unspecified vulnerabilities in Google V8.

  - Use-after-free vulnerability in the SpeechRecognitionClient implementation
  in the Speech subsystem.

  - common/partial_circular_buffer.cc script in Google Chrome does not properly
  handle wraps.

  - Vulnerability in core/html/parser/HTMLConstructionSite.cpp in the DOM
  implementation in Blink, as used in Google Chrome.

  - Vulnerability in core/dom/Document.cpp in Blink, as used in Google Chrome
  which allows the inheritance of the designMode attribute.

  - Use-after-free vulnerability in
  content/renderer/media/webaudio_capturer_source.cc  script in the WebAudio
  implementation.

  - Use-after-free vulnerability in the SVG implementation in Blink.

  - platform/graphics/filters/FEColorMatrix.cpp script in the SVG implementation
  in Blink.

  - Google Chrome relies on libvpx code that was not built with an appropriate
  size-limit value.

  - PDFium, as used in Google Chrome, does not properly initialize memory.

  - Multiple use-after-free vulnerabilities in
  content/renderer/media/user_media_client_impl.cc script in the WebRTC
  implementation.

  - Cross-site scripting (XSS) vulnerability in Google Chrome.

  - The Spellcheck API implementation in Google Chrome before does not use an
  HTTPS session for downloading a Hunspell dictionary.

  - platform/fonts/shaping/HarfBuzzShaper.cpp script in Blink, does not
  initialize a certain width field.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service, inject arbitrary web script, spoof the
  URL bar or deliver misleading popup content, bypass the Same Origin Policy and
  a sandbox protection mechanism, execute arbitrary code and allow
  man-in-the-middle attackers to deliver incorrect spelling suggestions or
  possibly have unspecified other impact via crafted dimensions.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  43.0.2357.65 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  43.0.2357.65 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2015/05/stable-channel-update_19.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74723");

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

if(version_is_less(version:chromeVer, test_version:"43.0.2357.65"))
{
  report = 'Installed version: ' + chromeVer + '\n' +
           'Fixed version:     43.0.2357.65'  + '\n';
  security_message(data:report);
  exit(0);
}
