# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0033");
  script_cve_id("CVE-2022-23521", "CVE-2022-41903");
  script_tag(name:"creation_date", value:"2023-03-28 00:26:44 +0000 (Tue, 28 Mar 2023)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-25 14:32:26 +0000 (Wed, 25 Jan 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0033)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0033");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0033.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31428");
  script_xref(name:"URL", value:"https://lore.kernel.org/git/xmqqa62g8i6u.fsf@gitster.g/T/");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.30.7.txt");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5810-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5810-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'git' package(s) announced via the MGASA-2023-0033 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"gitattributes are a mechanism to allow defining attributes for paths.
These attributes can be defined by adding a '.gitattributes' file to the
repository, which contains a set of file patterns and the attributes that
should be set for paths matching this pattern. When parsing gitattributes,
multiple integer overflows can occur when there is a huge number of path
patterns, a huge number of attributes for a single pattern, or when the
declared attribute names are huge. These overflows can be triggered via a
crafted '.gitattributes' file that may be part of the commit history. Git
silently splits lines longer than 2KB when parsing gitattributes from a
file, but not when parsing them from the index. Consequentially, the
failure mode depends on whether the file exists in the working tree, the
index or both. This integer overflow can result in arbitrary heap reads
and writes, which may result in remote code execution. (CVE-2022-23521)

'git log' can display commits in an arbitrary format using its '--format'
specifiers. This functionality is also exposed to 'git archive' via the
'export-subst' gitattribute. When processing the padding operators, there
is a integer overflow in 'pretty.c::format_and_pad_commit()' where a
'size_t' is stored improperly as an 'int, and then added as an offset to a
'memcpy()'. This overflow can be triggered directly by a user running a
command which invokes the commit formatting machinery
(e.g., 'git log --format=...'). It may also be triggered indirectly
through git archive via the export-subst mechanism, which expands format
specifiers inside of files within the repository during a git archive.
This integer overflow can result in arbitrary heap writes, which may
result in arbitrary code execution. (CVE-2022-41903)");

  script_tag(name:"affected", value:"'git' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"git", rpm:"git~2.30.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-arch", rpm:"git-arch~2.30.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-core", rpm:"git-core~2.30.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-core-oldies", rpm:"git-core-oldies~2.30.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-cvs", rpm:"git-cvs~2.30.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-email", rpm:"git-email~2.30.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-prompt", rpm:"git-prompt~2.30.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-subtree", rpm:"git-subtree~2.30.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-svn", rpm:"git-svn~2.30.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gitk", rpm:"gitk~2.30.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gitweb", rpm:"gitweb~2.30.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64git-devel", rpm:"lib64git-devel~2.30.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgit-devel", rpm:"libgit-devel~2.30.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Git", rpm:"perl-Git~2.30.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Git-SVN", rpm:"perl-Git-SVN~2.30.7~1.mga8", rls:"MAGEIA8"))) {
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
