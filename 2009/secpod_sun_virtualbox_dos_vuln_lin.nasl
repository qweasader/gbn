# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901055");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-11-26 06:39:46 +0100 (Thu, 26 Nov 2009)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3940");
  script_name("Sun VirtualBox or xVM VirtualBox Denial Of Service Vulnerability - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37363/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37024");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/387766.php");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-271149-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_sun_virtualbox_detect_lin.nasl");
  script_mandatory_keys("Sun/VirtualBox/Lin/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let attacker to exhaust the kernel memory of the
  guest operating system, leading to a Denial of Service against the guest
  operating system running in a virtual machine.");
  script_tag(name:"affected", value:"Sun VirtualBox version 3.x before 3.0.10
  Sun xVM VirtualBox 1.6.x and 2.0.x before 2.0.12, 2.1.x, and 2.2.x");
  script_tag(name:"insight", value:"The flaw is due to the unspecified vulnerability in Guest Additions,
  via unknown vectors.");
  script_tag(name:"solution", value:"Upgrade to Sun VirtualBox version 3.0.10 or Sun xVM VirtualBox 2.0.12.");
  script_tag(name:"summary", value:"Sun VirtualBox or xVM VirtualBox is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vmVer = get_kb_item("Sun/VirtualBox/Lin/Ver");
if(!vmVer)
  exit(0);

vmVer = eregmatch(pattern:"([0-9]\.[0-9]+\.[0-9]+)", string:vmVer);
if(!vmVer[1])
  exit(0);

if(version_in_range(version:vmVer[1], test_version:"1.6.0", test_version2:"1.6.6")||
   version_in_range(version:vmVer[1], test_version:"2.0.0", test_version2:"2.0.11")||
   version_in_range(version:vmVer[1], test_version:"2.1.0", test_version2:"2.1.4")||
   version_in_range(version:vmVer[1], test_version:"2.2.0", test_version2:"2.2.4")||
   version_in_range(version:vmVer[1], test_version:"3.0.0", test_version2:"3.0.9")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
