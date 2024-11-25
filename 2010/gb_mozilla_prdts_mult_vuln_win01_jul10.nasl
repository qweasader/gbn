# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801386");
  script_version("2024-02-12T14:37:47+0000");
  script_tag(name:"last_modification", value:"2024-02-12 14:37:47 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)");
  script_cve_id("CVE-2010-1208", "CVE-2010-1209", "CVE-2010-1206",
                "CVE-2010-1214", "CVE-2010-2751");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 16:10:03 +0000 (Fri, 02 Feb 2024)");
  script_name("Mozilla Products Multiple Vulnerabilities (MFSA2010-35, MFSA2010-36, MFSA2010-37, MFSA2010-43, MFSA2010-45) - Windows");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-35.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41824");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-36.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-37.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-43.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-45.html");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause a denial of service
  or execute arbitrary code.");

  script_tag(name:"affected", value:"Seamonkey version 2.0.x before 2.0.6

  Firefox version 3.5.x before 3.5.11 and 3.6.x before 3.6.7");

  script_tag(name:"insight", value:"The flaws are due to:

  - An error in the 'DOM' attribute cloning routine where under certain
  circumstances an event attribute node can be deleted while another object
  still contains a reference to it.

  - An error in Mozilla's implementation of NodeIterator in which a malicious
  NodeFilter could be created which would detach nodes from the DOM tree while
  it was being traversed.

  - An error in the code used to store the names and values of plugin parameter
  elements. A malicious page could embed plugin content containing a very
  large number of parameter elements which would cause an overflow in the
  integer value counting them.

  - An error in handling of location bar could be spoofed to look like a secure
  page when the current document was served via plain text.

  - Spoofing method does not require that the resource opened in a new window
  respond with 204, as long as the opener calls window.stop() before the
  document is loaded.

  - Spoofing error occurs when opening a new window containing a resource that
  responds with an HTTP 204 (no content) and then using the reference to the
  new window to insert HTML content into the blank document.");

  script_tag(name:"summary", value:"Mozilla Firefox/Seamonkey are prone to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.5.11 or 3.6.7

  Upgrade to Seamonkey version 2.0.6");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_in_range(version:ffVer, test_version:"3.6", test_version2:"3.6.6") ||
     version_in_range(version:ffVer, test_version:"3.5", test_version2:"3.5.10"))
     {
       security_message( port: 0, data: "The target host was found to be vulnerable" );
       exit(0);
     }
}

smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer)
{
  if(version_in_range(version:smVer, test_version:"2.0", test_version2:"2.0.5")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
