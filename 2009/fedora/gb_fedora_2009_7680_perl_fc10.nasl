# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64402");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
  script_cve_id("CVE-2009-1391", "CVE-2008-2827", "CVE-2007-4829");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 10 FEDORA-2009-7680 (perl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"Update Information:

This security update fixes an off-by-one overflow in Compress::Raw::Zlib
(CVE-2009-1391)  Moreover, it contains a subtle change to the configuration that
does not affect the Perl interpreter itself, but fixes the propagation of the
chosen options to the modules.  For example, a rebuild of perl-Wx against
perl-5.10.0-73 will fix bug 508496.

ChangeLog:

  * Tue Jul  7 2009 Stepan Kasal  - 4:5.10.0-73

  - re-enable tests

  * Tue Jul  7 2009 Stepan Kasal  - 4:5.10.0-72

  - move -DPERL_USE_SAFE_PUTENV to ccflags (#508496)

  * Mon Jun  8 2009 Marcela Mal�ov�  - 4:5.10.0-71

  - #504386 update of Compress::Raw::Zlib 2.020

  * Thu Jun  4 2009 Marcela Mal�ov�  - 4:5.10.0-70

  - update File::Spec (PathTools) to 3.30

  * Wed Jun  3 2009 Stepan Kasal  - 4:5.10.0-69

  - fix #221113, $! wrongly set when EOF is reached");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update perl' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-7680");
  script_tag(name:"summary", value:"The remote host is missing an update to perl
announced via advisory FEDORA-2009-7680.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=504386");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=508496");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"perl", rpm:"perl~5.10.0~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Archive-Extract", rpm:"perl-Archive-Extract~0.30~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Archive-Tar", rpm:"perl-Archive-Tar~1.46~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-CPAN", rpm:"perl-CPAN~1.9205~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-CPANPLUS", rpm:"perl-CPANPLUS~0.84~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Compress-Raw", rpm:"perl-Compress-Raw~Zlib~2.008", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Compress-Zlib", rpm:"perl-Compress-Zlib~2.008~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Digest-SHA", rpm:"perl-Digest-SHA~5.47~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-ExtUtils-CBuilder", rpm:"perl-ExtUtils-CBuilder~0.24~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-ExtUtils-Embed", rpm:"perl-ExtUtils-Embed~1.28~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-ExtUtils-MakeMaker", rpm:"perl-ExtUtils-MakeMaker~6.36~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-ExtUtils-ParseXS", rpm:"perl-ExtUtils-ParseXS~2.18~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-File-Fetch", rpm:"perl-File-Fetch~0.18~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-IO-Compress", rpm:"perl-IO-Compress~Base~2.008", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-IO-Compress", rpm:"perl-IO-Compress~Zlib~2.008", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-IO-Zlib", rpm:"perl-IO-Zlib~1.07~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-IPC-Cmd", rpm:"perl-IPC-Cmd~0.42~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Locale-Maketext", rpm:"perl-Locale-Maketext~Simple~0.18", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Log-Message", rpm:"perl-Log-Message~0.01~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Log-Message", rpm:"perl-Log-Message~Simple~0.04", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Module-Build", rpm:"perl-Module-Build~0.3200~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Module-CoreList", rpm:"perl-Module-CoreList~2.17~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Module-Load", rpm:"perl-Module-Load~0.12~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Module-Load", rpm:"perl-Module-Load~Conditional~0.30", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Module-Loaded", rpm:"perl-Module-Loaded~0.01~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Module-Pluggable", rpm:"perl-Module-Pluggable~3.60~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Object-Accessor", rpm:"perl-Object-Accessor~0.32~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Package-Constants", rpm:"perl-Package-Constants~0.01~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Params-Check", rpm:"perl-Params-Check~0.26~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Pod-Escapes", rpm:"perl-Pod-Escapes~1.04~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Pod-Simple", rpm:"perl-Pod-Simple~3.07~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Term-UI", rpm:"perl-Term-UI~0.18~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Test-Harness", rpm:"perl-Test-Harness~3.16~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Test-Simple", rpm:"perl-Test-Simple~0.86~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Time-Piece", rpm:"perl-Time-Piece~1.12~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-core", rpm:"perl-core~5.10.0~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-devel", rpm:"perl-devel~5.10.0~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-libs", rpm:"perl-libs~5.10.0~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-suidperl", rpm:"perl-suidperl~5.10.0~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-version", rpm:"perl-version~0.74~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-debuginfo", rpm:"perl-debuginfo~5.10.0~73.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
