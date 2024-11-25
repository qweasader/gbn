# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0043.1");
  script_cve_id("CVE-2017-12563", "CVE-2017-12691", "CVE-2017-13061", "CVE-2017-13062", "CVE-2017-14042", "CVE-2017-14174", "CVE-2017-14343", "CVE-2017-15277", "CVE-2017-15281");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:49 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:49+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:49 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-19 21:12:48 +0000 (Thu, 19 Oct 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0043-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0043-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180043-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2018:0043-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes several issues.
These security issues were fixed:
- CVE-2017-14343: Fixed a memory leak vulnerability in ReadXCFImage in
 coders/xcf.c via a crafted xcf image file (bsc#1058422).
- CVE-2017-12691: The ReadOneLayer function in coders/xcf.c allowed remote
 attackers to cause a denial of service (memory consumption) via a
 crafted file (bsc#1058422).
- CVE-2017-14042: Prevent memory allocation failure in the ReadPNMImage
 function in coders/pnm.c. The vulnerability caused a big memory
 allocation, which may have lead to remote denial of service in the
 MagickRealloc function in magick/memory.c (bsc#1056550).
- CVE-2017-15281: ReadPSDImage in coders/psd.c allowed remote attackers to
 cause a denial of service (application crash) or possibly have
 unspecified
 other impact via a crafted file (bsc#1063049).
- CVE-2017-13061: A length-validation vulnerability in the function
 ReadPSDLayersInternal in coders/psd.c allowed attackers to cause a
 denial of service (ReadPSDImage memory exhaustion) via a crafted file
 (bsc#1055063).
- CVE-2017-12563: A memory exhaustion vulnerability in the function
 ReadPSDImage in coders/psd.c allowed attackers to cause a denial of
 service (bsc#1052460).
- CVE-2017-14174: coders/psd.c allowed for DoS in ReadPSDLayersInternal()
 due to lack of an EOF (End of File) check might have caused huge CPU
 consumption. When a crafted PSD file, which claims a large 'length'
 field in the header but did not contain sufficient backing data, is
 provided, the loop over 'length' would consume huge CPU resources, since
 there is no EOF check inside the loop (bsc#1057723).
- CVE-2017-13062: A memory leak vulnerability in the function formatIPTC
 in coders/meta.c allowed attackers to cause a denial of service
 (WriteMETAImage memory consumption) via a crafted file (bsc#1055053).
- CVE-2017-15277: ReadGIFImage in coders/gif.c left the palette
 uninitialized when processing a GIF file that has neither a global nor
 local palette. If this functionality was used as a library loaded into a
 process that operates on interesting data, this data sometimes could
 have been leaked via the uninitialized palette (bsc#1063050).");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore1-32bit", rpm:"libMagickCore1-32bit~6.4.3.6~7.78.17.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore1", rpm:"libMagickCore1~6.4.3.6~7.78.17.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
