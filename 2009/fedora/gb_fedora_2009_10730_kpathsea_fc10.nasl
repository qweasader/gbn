# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66260");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-11-17 21:42:12 +0100 (Tue, 17 Nov 2009)");
  script_cve_id("CVE-2009-1284");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Fedora Core 10 FEDORA-2009-10730 (texlive)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"ChangeLog:

  * Fri Oct 23 2009 Jindrich Novy  2007-46

  - add missing dependency on kpathsea

  * Thu Oct 15 2009 Jindrich Novy  2007-45

  - make kpathsea not dependent on texlive

  - fix lacheck again (#451513)

  - fix dvips configuration (#467542)

  - update kpathsea description and summary (#519257)

  - use upstream patch to fix pool overflow CVE-2009-1284 (#492136)

  - don't complain if the pdvipsk hunks touching config.ps don't apply

  - avoid clashes with getline() from glibc

  - texlive-east-asian now requires texlive-texmf-east-asian (#487258)

  - do not attempt to remove old fonts via cron in /var/lib/texmf,
fonts are stored in ~/.texlive2007/texmf-var per-user
(#477833, #463975, #453468)

  - use correct paths in brp-* post install scriptlets (#468179)

  - fix build with gcc4.4");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update texlive' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-10730");
  script_tag(name:"summary", value:"The remote host is missing an update to texlive
announced via advisory FEDORA-2009-10730.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=492136");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"kpathsea", rpm:"kpathsea~2007~46.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kpathsea-devel", rpm:"kpathsea-devel~2007~46.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mendexk", rpm:"mendexk~2.6e~46.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"texlive", rpm:"texlive~2007~46.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"texlive-afm", rpm:"texlive-afm~2007~46.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"texlive-context", rpm:"texlive-context~2007~46.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"texlive-doc", rpm:"texlive-doc~2007~46.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"texlive-dvips", rpm:"texlive-dvips~2007~46.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"texlive-dviutils", rpm:"texlive-dviutils~2007~46.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"texlive-east-asian", rpm:"texlive-east-asian~2007~46.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"texlive-latex", rpm:"texlive-latex~2007~46.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"texlive-utils", rpm:"texlive-utils~2007~46.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"texlive-xetex", rpm:"texlive-xetex~2007~46.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"texlive-debuginfo", rpm:"texlive-debuginfo~2007~46.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
