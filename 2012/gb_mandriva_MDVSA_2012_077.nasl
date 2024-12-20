# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:077");
  script_oid("1.3.6.1.4.1.25623.1.0.831673");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2012-08-03 10:00:07 +0530 (Fri, 03 Aug 2012)");
  script_cve_id("CVE-2010-4167", "CVE-2012-0247", "CVE-2012-0248", "CVE-2012-1185",
                "CVE-2012-0259", "CVE-2012-0260", "CVE-2012-1798");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-31 18:39:00 +0000 (Fri, 31 Jul 2020)");
  script_xref(name:"MDVSA", value:"2012:077");
  script_name("Mandriva Update for imagemagick MDVSA-2012:077 (imagemagick)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'imagemagick'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_(mes5\.2|2010\.1)");
  script_tag(name:"affected", value:"imagemagick on Mandriva Enterprise Server 5.2,
  Mandriva Linux 2010.1");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been found and corrected in imagemagick:

  Untrusted search path vulnerability in configure.c in ImageMagick
  before 6.6.5-5, when MAGICKCORE_INSTALLED_SUPPORT is defined, allows
  local users to gain privileges via a Trojan horse configuration file
  in the current working directory (CVE-2010-4167).

  A flaw was found in the way ImageMagick processed images with malformed
  Exchangeable image file format (Exif) metadata. An attacker could
  create a specially-crafted image file that, when opened by a victim,
  would cause ImageMagick to crash or, potentially, execute arbitrary
  code (CVE-2012-0247).

  A denial of service flaw was found in the way ImageMagick processed
  images with malformed Exif metadata. An attacker could create a
  specially-crafted image file that, when opened by a victim, could
  cause ImageMagick to enter an infinite loop (CVE-2012-0248).

  The updated packages have been patched to correct these issues.

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_mes5.2")
{

  if ((res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~6.4.2.10~5.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~6.4.2.10~5.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~6.4.2.10~5.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmagick1", rpm:"libmagick1~6.4.2.10~5.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~6.4.2.10~5.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~6.4.2.10~5.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64magick1", rpm:"lib64magick1~6.4.2.10~5.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~6.4.2.10~5.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~6.6.1.5~2.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~6.6.1.5~2.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~6.6.1.5~2.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmagick3", rpm:"libmagick3~6.6.1.5~2.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~6.6.1.5~2.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~6.6.1.5~2.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64magick3", rpm:"lib64magick3~6.6.1.5~2.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~6.6.1.5~2.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
