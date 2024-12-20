# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801129");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-11-02 14:39:30 +0100 (Mon, 02 Nov 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3805");
  script_name("Gpg4Win Denial Of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_gpg4win_detect.nasl");
  script_mandatory_keys("Gpg4win_or_Kleopatra/Win/Installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53908");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36781");
  script_xref(name:"URL", value:"http://www.packetstormsecurity.com/0910-exploits/gpg2kleo-dos.txt");

  script_tag(name:"impact", value:"A remote attacker could exploit this vulnerability to cause the
  application to crash.");
  script_tag(name:"affected", value:"Gpg4win version 2.0.1 KDE, Kleopatra version 2.0.11");
  script_tag(name:"insight", value:"The flaw is due to error in 'gpg2.exe' which can be exploited by
  persuading a victim to import a specially-crafted certificate containing an
  overly long signature.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Gpg4Win, as used in KDE Kleopatra is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.gpg4win.org/download.html");
  exit(0);
}

include("version_func.inc");

gpgVer = get_kb_item("Gpg4win/Win/Ver");

kleoVer = get_kb_item("Kleopatra/Win/Ver");

if(version_is_equal(version:gpgVer, test_version:"2.0.1") &&
   version_is_equal(version:kleoVer,test_version:"2.0.11")){
  installed_version = "Gpg4win: " + gpgVer + ", Kleopatra: " + kleoVer;
  fixed_version = "Gpg4win: 2.0.2, Kleopatra: none available";
  report = report_fixed_ver(installed_version:installed_version, fixed_version:fixed_version);
  security_message(data:report);
  exit(0);
}

exit(99);