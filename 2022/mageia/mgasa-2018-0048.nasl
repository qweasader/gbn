# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0048");
  script_cve_id("CVE-2016-4658", "CVE-2016-5131", "CVE-2016-9318", "CVE-2017-0663", "CVE-2017-15412", "CVE-2017-16932", "CVE-2017-5130", "CVE-2017-5969", "CVE-2017-7375", "CVE-2017-7376", "CVE-2017-9047", "CVE-2017-9048", "CVE-2017-9049", "CVE-2017-9050");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-18 14:22:38 +0000 (Sun, 18 Mar 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0048)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0048");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0048.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19695");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/10/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/12/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2017-02/msg00055.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2017-06/msg00022.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2017-07/msg00000.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2017-07/msg00040.html");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/usn/usn-3504-1/");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/usn/usn-3513-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2, perl-XML-LibXML' package(s) announced via the MGASA-2018-0048 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Use-after-free error could lead to crash (CVE-2016-4658).

Use-after-free vulnerability in libxml2 through 2.9.4 allows remote
attackers to cause a denial of service or possibly have unspecified
other impact via vectors related to the XPointer range-to function
(CVE-2016-5131).

libxml2 2.9.4 and earlier does not offer a flag directly indicating that
the current document may be read but other files may not be opened,
which makes it easier for remote attackers to conduct XML External
Entity (XXE) attacks via a crafted document (CVE-2016-9318).

Heap buffer overflow in xmlAddID (CVE-2017-0663).

Integer overflow in memory debug code in libxml2 before 2.9.5
(CVE-2017-5130).

NULL pointer deref in xmlDumpElementContent (CVE-2017-5969).

Prevent unwanted external entity reference (CVE-2017-7375).

Increase buffer space for port in HTTP redirect support (CVE-2017-7376).

The function xmlSnprintfElementContent in valid.c was vulnerable to a
stack buffer overflow (CVE-2017-9047, CVE-2017-9048).

The function xmlDictComputeFastKey in dict.c was vulnerable to a
heap-based buffer over-read (CVE-2017-9049).

The function xmlDictAddString was vulnerable to a heap-based buffer
over-read (CVE-2017-9050).

It was discovered that libxml2 incorrecty handled certain files. An
attacker could use this issue with specially constructed XML data to
cause libxml2 to consume resources, leading to a denial of service
(CVE-2017-15412).

Wei Lei discovered that libxml2 incorrecty handled certain parameter
entities. An attacker could use this issue with specially constructed
XML data to cause libxml2 to consume resources, leading to a denial of
service (CVE-2017-16932).

The libxml2 package has been updated to version 2.9.7 to fix these
issues and several other bugs.");

  script_tag(name:"affected", value:"'libxml2, perl-XML-LibXML' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64xml2-devel", rpm:"lib64xml2-devel~2.9.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xml2_2", rpm:"lib64xml2_2~2.9.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.9.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.9.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-python", rpm:"libxml2-python~2.9.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-utils", rpm:"libxml2-utils~2.9.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2_2", rpm:"libxml2_2~2.9.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-XML-LibXML", rpm:"perl-XML-LibXML~2.12.100~1.2.mga5", rls:"MAGEIA5"))) {
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
