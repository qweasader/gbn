# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902739");
  script_version("2024-02-20T14:37:13+0000");
  script_tag(name:"last_modification", value:"2024-02-20 14:37:13 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-09-30 15:58:03 +0200 (Fri, 30 Sep 2011)");
  script_cve_id("CVE-2011-2426", "CVE-2011-2427", "CVE-2011-2428",
                "CVE-2011-2429", "CVE-2011-2430", "CVE-2011-2444");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Flash Player Multiple Vulnerabilities (Sep 2011) - Linux");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-26.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49710");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49714");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49715");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49716");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49717");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49718");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code or cause
  a denial of service.");
  script_tag(name:"affected", value:"Adobe Flash Player versions prior to 10.3.183.10 on Linux.");
  script_tag(name:"insight", value:"The flaws are due to

  - Stack-based buffer overflow in the ActionScript Virtual Machine (AVM)
    component, allows remote attackers to execute arbitrary code via
    unspecified vectors.

  - security control bypass, allows attackers to bypass intended access
    restrictions and obtain sensitive information via unspecified vectors

  - logic error vulnerability, allows remote attackers to cause a denial of
    service (browser crash) via unspecified vectors or execute arbitrary via
    crafted streaming media.

  - Cross-site scripting (XSS) vulnerability, allows remote attackers to
    inject arbitrary web script or HTML via a crafted URL.");
  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version 10.3.183.10 or later.");
  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(!vers)
  exit(0);

vers = ereg_replace(pattern:",", string:vers, replace: ".");

if(version_is_less(version:vers, test_version:"10.3.183.10")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"10.3.183.10");
  security_message(port: 0, data: report);
}
