# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:106");
  script_oid("1.3.6.1.4.1.25623.1.0.831694");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-16 11:57:41 +0530 (Mon, 16 Jul 2012)");
  script_cve_id("CVE-2012-2812", "CVE-2012-2813", "CVE-2012-2814", "CVE-2012-2836",
                "CVE-2012-2837", "CVE-2012-2840", "CVE-2012-2841");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"MDVSA", value:"2012:106");
  script_name("Mandriva Update for libexif MDVSA-2012:106 (libexif)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libexif'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_(2011\.0|mes5\.2)");
  script_tag(name:"affected", value:"libexif on Mandriva Linux 2011.0,
  Mandriva Enterprise Server 5.2");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been discovered and corrected in libexif:

  A heap-based out-of-bounds array read in the exif_entry_get_value
  function in libexif/exif-entry.c in libexif 0.6.20 and earlier allows
  remote attackers to cause a denial of service or possibly obtain
  potentially sensitive information from process memory via an image
  with crafted EXIF tags (CVE-2012-2812).

  A heap-based out-of-bounds array read in the exif_convert_utf16_to_utf8
  function in libexif/exif-entry.c in libexif 0.6.20 and earlier allows
  remote attackers to cause a denial of service or possibly obtain
  potentially sensitive information from process memory via an image
  with crafted EXIF tags (CVE-2012-2813).

  A buffer overflow in the exif_entry_format_value function in
  libexif/exif-entry.c in libexif 0.6.20 allows remote attackers to
  cause a denial of service or possibly execute arbitrary code via an
  image with crafted EXIF tags (CVE-2012-2814).

  A heap-based out-of-bounds array read in the exif_data_load_data
  function in libexif 0.6.20 and earlier allows remote attackers to
  cause a denial of service or possibly obtain potentially sensitive
  information from process memory via an image with crafted EXIF tags
  (CVE-2012-2836).

  A divide-by-zero error in the mnote_olympus_entry_get_value function
  while formatting EXIF maker note tags in libexif 0.6.20 and earlier
  allows remote attackers to cause a denial of service via an image
  with crafted EXIF tags (CVE-2012-2837).

  An off-by-one error in the exif_convert_utf16_to_utf8 function in
  libexif/exif-entry.c in libexif 0.6.20 and earlier allows remote
  attackers to cause a denial of service or possibly execute arbitrary
  code via an image with crafted EXIF tags (CVE-2012-2840).

  An integer underflow in the exif_entry_get_value function can cause a
  heap overflow and potentially arbitrary code execution while formatting
  an EXIF tag, if the function is called with a buffer size parameter
  equal to zero or one (CVE-2012-2841).

  The updated packages have been upgraded to the 0.6.21 version which
  is not vulnerable to these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_2011.0")
{

  if ((res = isrpmvuln(pkg:"libexif12", rpm:"libexif12~0.6.21~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libexif12-common", rpm:"libexif12-common~0.6.21~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libexif-devel", rpm:"libexif-devel~0.6.21~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64exif12", rpm:"lib64exif12~0.6.21~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64exif-devel", rpm:"lib64exif-devel~0.6.21~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_mes5.2")
{

  if ((res = isrpmvuln(pkg:"libexif12", rpm:"libexif12~0.6.21~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libexif12-common", rpm:"libexif12-common~0.6.21~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libexif-devel", rpm:"libexif-devel~0.6.21~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64exif12", rpm:"lib64exif12~0.6.21~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64exif-devel", rpm:"lib64exif-devel~0.6.21~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
