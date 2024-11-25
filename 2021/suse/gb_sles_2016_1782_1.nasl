# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1782.1");
  script_cve_id("CVE-2014-9805", "CVE-2014-9806", "CVE-2014-9807", "CVE-2014-9808", "CVE-2014-9809", "CVE-2014-9810", "CVE-2014-9811", "CVE-2014-9812", "CVE-2014-9813", "CVE-2014-9814", "CVE-2014-9815", "CVE-2014-9816", "CVE-2014-9817", "CVE-2014-9818", "CVE-2014-9819", "CVE-2014-9820", "CVE-2014-9822", "CVE-2014-9823", "CVE-2014-9824", "CVE-2014-9826", "CVE-2014-9828", "CVE-2014-9829", "CVE-2014-9830", "CVE-2014-9831", "CVE-2014-9834", "CVE-2014-9835", "CVE-2014-9836", "CVE-2014-9837", "CVE-2014-9838", "CVE-2014-9839", "CVE-2014-9840", "CVE-2014-9842", "CVE-2014-9844", "CVE-2014-9845", "CVE-2014-9846", "CVE-2014-9847", "CVE-2014-9849", "CVE-2014-9851", "CVE-2014-9853", "CVE-2014-9854", "CVE-2015-8894", "CVE-2015-8896", "CVE-2015-8897", "CVE-2015-8898", "CVE-2015-8901", "CVE-2015-8902", "CVE-2015-8903", "CVE-2016-4562", "CVE-2016-4563", "CVE-2016-4564", "CVE-2016-5687", "CVE-2016-5688", "CVE-2016-5689", "CVE-2016-5690", "CVE-2016-5691", "CVE-2016-5841", "CVE-2016-5842");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:05 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-15 03:02:17 +0000 (Thu, 15 Dec 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1782-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1782-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161782-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2016:1782-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ImageMagick was updated to fix 55 security issues.
These security issues were fixed:
- CVE-2014-9810: SEGV in dpx file handler (bsc#983803).
- CVE-2014-9811: Crash in xwd file handler (bsc#984032).
- CVE-2014-9812: NULL pointer dereference in ps file handling (bsc#984137).
- CVE-2014-9813: Crash on corrupted viff file (bsc#984035).
- CVE-2014-9814: NULL pointer dereference in wpg file handling
 (bsc#984193).
- CVE-2014-9815: Crash on corrupted wpg file (bsc#984372).
- CVE-2014-9816: Out of bound access in viff image (bsc#984398).
- CVE-2014-9817: Heap buffer overflow in pdb file handling (bsc#984400).
- CVE-2014-9818: Out of bound access on malformed sun file (bsc#984181).
- CVE-2014-9819: Heap overflow in palm files (bsc#984142).
- CVE-2014-9830: Handling of corrupted sun file (bsc#984135).
- CVE-2014-9831: Handling of corrupted wpg file (bsc#984375).
- CVE-2014-9836: Crash in xpm file handling (bsc#984023).
- CVE-2014-9851: Crash when parsing resource block (bsc#984160).
- CVE-2016-5689: NULL ptr dereference in dcm coder (bsc#985460).
- CVE-2014-9853: Memory leak in rle file handling (bsc#984408).
- CVE-2015-8902: PDB file DoS (CPU consumption) (bsc#983253).
- CVE-2015-8903: Denial of service (cpu) in vicar (bsc#983259).
- CVE-2015-8901: MIFF file DoS (endless loop) (bsc#983234).
- CVE-2014-9834: Heap overflow in pict file (bsc#984436).
- CVE-2014-9806: Prevent file descriptr leak due to corrupted file
 (bsc#983774).
- CVE-2014-9838: Out of memory crash in magick/cache.c (bsc#984370).
- CVE-2014-9854: Filling memory during identification of TIFF image
 (bsc#984184).
- CVE-2015-8898: Prevent null pointer access in magick/constitute.c
 (bsc#983746).
- CVE-2015-8894: Double free in coders/tga.c:221 (bsc#983523).
- CVE-2015-8896: Double free / integer truncation issue in
 coders/pict.c:2000 (bsc#983533).
- CVE-2015-8897: Out of bounds error in SpliceImage (bsc#983739).
- CVE-2016-5690: Bad foor loop in DCM coder (bsc#985451).
- CVE-2016-5691: Checks for pixel.red/green/blue in dcm coder (bsc#985456).
- CVE-2014-9805: SEGV due to a corrupted pnm file. (bsc#983752).
- CVE-2014-9808: SEGV due to corrupted dpc images. (bsc#983796).
- CVE-2014-9820: heap overflow in xpm files (bsc#984150).
- CVE-2014-9823: heap overflow in palm file (bsc#984401).
- CVE-2014-9822: heap overflow in quantum file (bsc#984187).
- CVE-2014-9839: Theoretical out of bound access in
 magick/colormap-private.h (bsc#984379).
- CVE-2014-9824: Heap overflow in psd file (bsc#984185).
- CVE-2014-9809: Fix a SEGV due to corrupted xwd images. (bsc#983799).
- CVE-2014-9826: Incorrect error handling in sun files (bsc#984186).
- CVE-2014-9842: Memory leak in psd handling (bsc#984374).
- CVE-2016-5687: Out of bounds read in DDS coder (bsc#985448).
- CVE-2014-9840: Out of bound access in palm file (bsc#984433).
- CVE-2014-9847: Incorrect handling of 'previous' image in the JNG decoder
 (bsc#984144).
- CVE-2014-9846: ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore1-32bit", rpm:"libMagickCore1-32bit~6.4.3.6~7.45.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore1", rpm:"libMagickCore1~6.4.3.6~7.45.1", rls:"SLES11.0SP4"))) {
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
