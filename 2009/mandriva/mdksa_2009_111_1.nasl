# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63983");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-05-20 00:17:15 +0200 (Wed, 20 May 2009)");
  script_cve_id("CVE-2009-1302", "CVE-2009-1303", "CVE-2009-1304", "CVE-2009-1305", "CVE-2009-0652", "CVE-2009-1306", "CVE-2009-1307", "CVE-2009-1308", "CVE-2009-1309", "CVE-2009-1310", "CVE-2009-1311", "CVE-2009-1312", "CVE-2009-1313");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mandrake Security Advisory MDVSA-2009:111-1 (firefox)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_2009\.0");
  script_tag(name:"insight", value:"Security vulnerabilities have been discovered in previous
versions, and corrected in the latest Mozilla Firefox 3.x, version
3.0.10. (CVE-2009-1302, CVE-2009-1303, CVE-2009-1304, CVE-2009-1305,
CVE-2009-0652, CVE-2009-1306, CVE-2009-1307, CVE-2009-1308,
CVE-2009-1309, CVE-2009-1310, CVE-2009-1311, CVE-2009-1312,
CVE-2009-1313)

This update provides the latest Mozilla Firefox 3.x to correct
these issues.

Additionally, some packages which require so, have been rebuilt and
are being provided as updates.

Update:

The recent Mozilla Firefox update missed the Firefox language packs
for Mandriva Linux 2009. This update provides them, fixing the issue.

Affected: 2009.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:111-1");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/known-vulnerabilities/firefox30.html#firefox3.0.10");
  script_tag(name:"summary", value:"The remote host is missing an update to firefox
announced via advisory MDVSA-2009:111-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"firefox-af", rpm:"firefox-af~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ar", rpm:"firefox-ar~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-be", rpm:"firefox-be~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-bg", rpm:"firefox-bg~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-bn", rpm:"firefox-bn~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ca", rpm:"firefox-ca~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-cs", rpm:"firefox-cs~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-cy", rpm:"firefox-cy~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-da", rpm:"firefox-da~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-de", rpm:"firefox-de~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-el", rpm:"firefox-el~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-en_GB", rpm:"firefox-en_GB~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-eo", rpm:"firefox-eo~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-es_AR", rpm:"firefox-es_AR~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-es_ES", rpm:"firefox-es_ES~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-et", rpm:"firefox-et~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-eu", rpm:"firefox-eu~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-fi", rpm:"firefox-fi~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-fr", rpm:"firefox-fr~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-fy", rpm:"firefox-fy~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ga_IE", rpm:"firefox-ga_IE~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-gl", rpm:"firefox-gl~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-gu_IN", rpm:"firefox-gu_IN~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-he", rpm:"firefox-he~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-hi", rpm:"firefox-hi~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-hu", rpm:"firefox-hu~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-id", rpm:"firefox-id~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-is", rpm:"firefox-is~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-it", rpm:"firefox-it~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ja", rpm:"firefox-ja~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ka", rpm:"firefox-ka~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-kn", rpm:"firefox-kn~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ko", rpm:"firefox-ko~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ku", rpm:"firefox-ku~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-lt", rpm:"firefox-lt~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-lv", rpm:"firefox-lv~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-mk", rpm:"firefox-mk~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-mn", rpm:"firefox-mn~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-mr", rpm:"firefox-mr~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-nb_NO", rpm:"firefox-nb_NO~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-nl", rpm:"firefox-nl~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-nn_NO", rpm:"firefox-nn_NO~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-oc", rpm:"firefox-oc~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-pa_IN", rpm:"firefox-pa_IN~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-pl", rpm:"firefox-pl~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-pt_BR", rpm:"firefox-pt_BR~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-pt_PT", rpm:"firefox-pt_PT~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ro", rpm:"firefox-ro~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ru", rpm:"firefox-ru~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-si", rpm:"firefox-si~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-sk", rpm:"firefox-sk~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-sl", rpm:"firefox-sl~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-sq", rpm:"firefox-sq~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-sr", rpm:"firefox-sr~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-sv_SE", rpm:"firefox-sv_SE~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-te", rpm:"firefox-te~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-th", rpm:"firefox-th~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-tr", rpm:"firefox-tr~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-uk", rpm:"firefox-uk~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-zh_CN", rpm:"firefox-zh_CN~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-zh_TW", rpm:"firefox-zh_TW~3.0.10~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
