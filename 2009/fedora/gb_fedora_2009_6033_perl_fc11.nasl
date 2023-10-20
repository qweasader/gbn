# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64223");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-06-23 15:49:15 +0200 (Tue, 23 Jun 2009)");
  script_cve_id("CVE-2009-1391");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 11 FEDORA-2009-6033 (perl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC11");
  script_tag(name:"insight", value:"Update Information:

Off-by-one overflow in Compress::Raw::Zlib (CVE-2009-1391)

ChangeLog:

  * Mon Jun  8 2009 Marcela Mal�ov�  - 4:5.10.0-69

  - #504386 update of Compress::Raw::Zlib 2.020

  - update File::Spec (PathTools) to 3.30

  - fix #221113, $! wrongly set when EOF is reached");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update perl' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-6033");
  script_tag(name:"summary", value:"The remote host is missing an update to perl
announced via advisory FEDORA-2009-6033.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=504386");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"perl", rpm:"perl~5.10.0~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Archive-Extract", rpm:"perl-Archive-Extract~0.30~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Archive-Tar", rpm:"perl-Archive-Tar~1.46~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-CPAN", rpm:"perl-CPAN~1.9205~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-CPANPLUS", rpm:"perl-CPANPLUS~0.84~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Compress-Raw", rpm:"perl-Compress-Raw~Zlib~2.008", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Compress-Zlib", rpm:"perl-Compress-Zlib~2.008~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Digest-SHA", rpm:"perl-Digest-SHA~5.47~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-ExtUtils-CBuilder", rpm:"perl-ExtUtils-CBuilder~0.24~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-ExtUtils-Embed", rpm:"perl-ExtUtils-Embed~1.28~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-ExtUtils-MakeMaker", rpm:"perl-ExtUtils-MakeMaker~6.36~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-ExtUtils-ParseXS", rpm:"perl-ExtUtils-ParseXS~2.18~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-File-Fetch", rpm:"perl-File-Fetch~0.18~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-IO-Compress", rpm:"perl-IO-Compress~Base~2.008", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-IO-Compress", rpm:"perl-IO-Compress~Zlib~2.008", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-IO-Zlib", rpm:"perl-IO-Zlib~1.07~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-IPC-Cmd", rpm:"perl-IPC-Cmd~0.42~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Locale-Maketext", rpm:"perl-Locale-Maketext~Simple~0.18", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Log-Message", rpm:"perl-Log-Message~0.01~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Log-Message", rpm:"perl-Log-Message~Simple~0.04", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Module-Build", rpm:"perl-Module-Build~0.3200~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Module-CoreList", rpm:"perl-Module-CoreList~2.17~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Module-Load", rpm:"perl-Module-Load~0.12~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Module-Load", rpm:"perl-Module-Load~Conditional~0.30", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Module-Loaded", rpm:"perl-Module-Loaded~0.01~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Module-Pluggable", rpm:"perl-Module-Pluggable~3.60~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Object-Accessor", rpm:"perl-Object-Accessor~0.32~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Package-Constants", rpm:"perl-Package-Constants~0.01~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Params-Check", rpm:"perl-Params-Check~0.26~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Pod-Escapes", rpm:"perl-Pod-Escapes~1.04~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Pod-Simple", rpm:"perl-Pod-Simple~3.07~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Term-UI", rpm:"perl-Term-UI~0.18~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Test-Harness", rpm:"perl-Test-Harness~3.16~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Test-Simple", rpm:"perl-Test-Simple~0.86~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Time-Piece", rpm:"perl-Time-Piece~1.12~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-core", rpm:"perl-core~5.10.0~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-devel", rpm:"perl-devel~5.10.0~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-libs", rpm:"perl-libs~5.10.0~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-suidperl", rpm:"perl-suidperl~5.10.0~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-version", rpm:"perl-version~0.74~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-debuginfo", rpm:"perl-debuginfo~5.10.0~69.fc11", rls:"FC11")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
