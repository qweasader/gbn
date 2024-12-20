# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0062");
  script_cve_id("CVE-2018-14325", "CVE-2018-14326", "CVE-2018-14379", "CVE-2018-14403", "CVE-2018-14446");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-18 19:46:00 +0000 (Tue, 18 Sep 2018)");

  script_name("Mageia: Security Advisory (MGASA-2020-0062)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0062");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0062.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25962");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/6YCHVOYPIBGM5HYUMQ77KZH2IHSITKVE/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libmp4v2' package(s) announced via the MGASA-2020-0062 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libmp4v2 packages fix security vulnerabilities:

The libmp4v2 library through version 2.1.0 is vulnerable to an integer
underflow when parsing an MP4Atom in mp4atom.cpp. An attacker could exploit
this to cause a denial of service via crafted MP4 file (CVE-2018-14325).

The libmp4v2 library through version 2.1.0 is vulnerable to an integer
overflow and resultant heap-based buffer overflow when resizing an MP4Array
for the ftyp atom in mp4array.h. An attacker could exploit this to cause a
denial of service via crafted MP4 file (CVE-2018-14326).

MP4Atom::factory in mp4atom.cpp in MP4v2 2.0.0 incorrectly uses the
MP4ItemAtom data type in a certain case where MP4DataAtom is required, which
allows remote attackers to cause a denial of service (memory corruption) or
possibly have unspecified other impact via a crafted MP4 file, because access
to the data structure has different expectations about layout as a result of
this type confusion (CVE-2018-14379).

MP4NameFirstMatches in mp4util.cpp in MP4v2 2.0.0 mishandles substrings of
atom names, leading to use of an inappropriate data type for associated atoms.
The resulting type confusion can cause out-of-bounds memory access
(CVE-2018-14403).

MP4Integer32Property::Read in atom_avcC.cpp in MP4v2 2.1.0 allows remote
attackers to cause a denial of service (heap-based buffer overflow and
application crash) or possibly have unspecified other impact via a crafted
MP4 file (CVE-2018-14446).");

  script_tag(name:"affected", value:"'libmp4v2' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"lib64mp4v2-devel", rpm:"lib64mp4v2-devel~2.1.0~0.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mp4v2_2", rpm:"lib64mp4v2_2~2.1.0~0.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmp4v2", rpm:"libmp4v2~2.1.0~0.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmp4v2-devel", rpm:"libmp4v2-devel~2.1.0~0.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmp4v2-utils", rpm:"libmp4v2-utils~2.1.0~0.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmp4v2_2", rpm:"libmp4v2_2~2.1.0~0.4.mga7", rls:"MAGEIA7"))) {
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
