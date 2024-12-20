# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64606");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
  script_cve_id("CVE-2009-2412", "CVE-2009-2411");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mandrake Security Advisory MDVSA-2009:199 (subversion)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.1|2009\.0|2009\.1|4\.0|mes5)");
  script_tag(name:"insight", value:"A vulnerability has been found and corrected in subversion:

Multiple integer overflows in the libsvn_delta library in Subversion
before 1.5.7, and 1.6.x before 1.6.4, allow remote authenticated users
and remote Subversion servers to execute arbitrary code via an svndiff
stream with large windows that trigger a heap-based buffer overflow,
a related issue to CVE-2009-2412 (CVE-2009-2411).

This update provides a solution to this vulnerability and in turn
upgrades subversion where possible to provide additional features
and upstream bugfixes and adds required dependencies where needed.

Affected: 2008.1, 2009.0, 2009.1, Corporate 4.0, Enterprise Server 5.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:199");
  script_tag(name:"summary", value:"The remote host is missing an update to subversion
announced via advisory MDVSA-2009:199.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"apache-mod_dav_svn", rpm:"apache-mod_dav_svn~1.4.6~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_dontdothat", rpm:"apache-mod_dontdothat~1.4.6~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsvn0", rpm:"libsvn0~1.4.6~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-SVN", rpm:"perl-SVN~1.4.6~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-SVN-devel", rpm:"perl-SVN-devel~1.4.6~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-svn", rpm:"python-svn~1.4.6~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-svn-devel", rpm:"python-svn-devel~1.4.6~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-svn", rpm:"ruby-svn~1.4.6~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-svn-devel", rpm:"ruby-svn-devel~1.4.6~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion", rpm:"subversion~1.4.6~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-devel", rpm:"subversion-devel~1.4.6~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-doc", rpm:"subversion-doc~1.4.6~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-server", rpm:"subversion-server~1.4.6~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-tools", rpm:"subversion-tools~1.4.6~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"svn-javahl", rpm:"svn-javahl~1.4.6~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"svn-javahl-javadoc", rpm:"svn-javahl-javadoc~1.4.6~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64svn0", rpm:"lib64svn0~1.4.6~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_dav_svn", rpm:"apache-mod_dav_svn~1.5.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_dontdothat", rpm:"apache-mod_dontdothat~1.5.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsvn0", rpm:"libsvn0~1.5.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsvnjavahl0", rpm:"libsvnjavahl0~1.5.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-SVN", rpm:"perl-SVN~1.5.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-svn", rpm:"python-svn~1.5.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-svn", rpm:"ruby-svn~1.5.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion", rpm:"subversion~1.5.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-devel", rpm:"subversion-devel~1.5.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-doc", rpm:"subversion-doc~1.5.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-server", rpm:"subversion-server~1.5.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-tools", rpm:"subversion-tools~1.5.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"svn-javahl", rpm:"svn-javahl~1.5.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64svn0", rpm:"lib64svn0~1.5.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64svnjavahl0", rpm:"lib64svnjavahl0~1.5.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_dav_svn", rpm:"apache-mod_dav_svn~1.6.4~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_dontdothat", rpm:"apache-mod_dontdothat~1.6.4~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsvn0", rpm:"libsvn0~1.6.4~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsvnjavahl1", rpm:"libsvnjavahl1~1.6.4~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-SVN", rpm:"perl-SVN~1.6.4~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-svn", rpm:"python-svn~1.6.4~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-svn", rpm:"ruby-svn~1.6.4~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion", rpm:"subversion~1.6.4~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-devel", rpm:"subversion-devel~1.6.4~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-doc", rpm:"subversion-doc~1.6.4~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-server", rpm:"subversion-server~1.6.4~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-tools", rpm:"subversion-tools~1.6.4~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"svn-javahl", rpm:"svn-javahl~1.6.4~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64svn0", rpm:"lib64svn0~1.6.4~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64svnjavahl1", rpm:"lib64svnjavahl1~1.6.4~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_dav_svn", rpm:"apache-mod_dav_svn~1.5.7~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_dontdothat", rpm:"apache-mod_dontdothat~1.5.7~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27", rpm:"libneon0.27~0.28.3~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27-devel", rpm:"libneon0.27-devel~0.28.3~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27-static-devel", rpm:"libneon0.27-static-devel~0.28.3~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libserf0", rpm:"libserf0~0.2.0~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libserf-devel", rpm:"libserf-devel~0.2.0~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsvn0", rpm:"libsvn0~1.5.7~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-SVN", rpm:"perl-SVN~1.5.7~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-svn", rpm:"python-svn~1.5.7~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion", rpm:"subversion~1.5.7~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-devel", rpm:"subversion-devel~1.5.7~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-doc", rpm:"subversion-doc~1.5.7~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-server", rpm:"subversion-server~1.5.7~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-tools", rpm:"subversion-tools~1.5.7~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27", rpm:"lib64neon0.27~0.28.3~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27-devel", rpm:"lib64neon0.27-devel~0.28.3~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27-static-devel", rpm:"lib64neon0.27-static-devel~0.28.3~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64serf0", rpm:"lib64serf0~0.2.0~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64serf-devel", rpm:"lib64serf-devel~0.2.0~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64svn0", rpm:"lib64svn0~1.5.7~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_dav_svn", rpm:"apache-mod_dav_svn~1.5.7~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_dontdothat", rpm:"apache-mod_dontdothat~1.5.7~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsvn0", rpm:"libsvn0~1.5.7~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsvnjavahl0", rpm:"libsvnjavahl0~1.5.7~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-SVN", rpm:"perl-SVN~1.5.7~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-svn", rpm:"python-svn~1.5.7~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-svn", rpm:"ruby-svn~1.5.7~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion", rpm:"subversion~1.5.7~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-devel", rpm:"subversion-devel~1.5.7~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-doc", rpm:"subversion-doc~1.5.7~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-server", rpm:"subversion-server~1.5.7~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"subversion-tools", rpm:"subversion-tools~1.5.7~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"svn-javahl", rpm:"svn-javahl~1.5.7~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64svn0", rpm:"lib64svn0~1.5.7~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64svnjavahl0", rpm:"lib64svnjavahl0~1.5.7~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
