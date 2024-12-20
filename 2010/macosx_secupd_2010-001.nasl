# SPDX-FileCopyrightText: 2010 LSS
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102020");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-04-06 10:41:02 +0200 (Tue, 06 Apr 2010)");
  script_name("Mac OS X Security Update 2010-001");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 16:04:42 +0000 (Fri, 02 Feb 2024)");
  script_category(ACT_GATHER_INFO);
  script_cve_id("CVE-2010-0036", "CVE-2009-3553", "CVE-2009-3794", "CVE-2009-3796", "CVE-2009-3797",
                "CVE-2009-3798", "CVE-2009-3799", "CVE-2009-3800", "CVE-2009-3951", "CVE-2009-2285",
                "CVE-2010-0037", "CVE-2009-3555");
  script_copyright("Copyright (C) 2010 LSS");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.[56]\.");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4004");

  script_tag(name:"summary", value:"The remote host is missing Mac OS X Security Update 2010-001.");

  script_tag(name:"affected", value:"One or more of the following components are affected:

  CoreAudio

 CUPS

 Flash Player plug-in

 ImageIO

 Image RAW

 OpenSSL");

  script_tag(name:"solution", value:"Update your Mac OS X operating system. Please see the references for more information.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-macosx.inc");
include("version_func.inc");

ssh_osx_name = get_kb_item("ssh/login/osx_name");
if (!ssh_osx_name) exit (0);

ssh_osx_ver = get_kb_item("ssh/login/osx_version");
if (!ssh_osx_ver || ssh_osx_ver !~ "^10\.[56]\.") exit (0);

ssh_osx_rls = ssh_osx_name + ' ' + ssh_osx_ver;

pkg_for_ver = make_list("Mac OS X 10.5.8","Mac OS X Server 10.5.8","Mac OS X 10.6.2","Mac OS X Server 10.6.2");

if (rlsnotsupported(rls:ssh_osx_rls, list:pkg_for_ver)) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0); }

if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X 10.5.8")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X 10.5.8"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0); }
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X 10.5.8")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2010.001"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0); }
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X Server 10.5.8")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X Server 10.5.8"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0); }
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X Server 10.5.8")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2010.001"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0); }
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X 10.6.2")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X 10.6.2"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0); }
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X 10.6.2")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2010.001"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0); }
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X Server 10.6.2")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X Server 10.6.2"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0); }
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X Server 10.6.2")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2010.001"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0); }
}
