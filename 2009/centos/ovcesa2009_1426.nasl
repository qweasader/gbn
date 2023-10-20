# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64831");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-09 02:15:49 +0200 (Wed, 09 Sep 2009)");
  script_cve_id("CVE-2009-0200", "CVE-2009-0201");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("CentOS Security Advisory CESA-2009:1426 (openoffice.org)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS(3|4)");
  script_tag(name:"insight", value:"For details on the issues addressed in this update,
please visit the referenced security advisories.");
  script_tag(name:"solution", value:"Update the appropriate packages on your system.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=CESA-2009:1426");
  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=RHSA-2009:1426");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2009-1426.html");
  script_tag(name:"summary", value:"The remote host is missing updates to openoffice.org announced in
advisory CESA-2009:1426.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"openoffice.org", rpm:"openoffice.org~1.1.2~44.2.0.EL3", rls:"CentOS3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-i18n", rpm:"openoffice.org-i18n~1.1.2~44.2.0.EL3", rls:"CentOS3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-libs", rpm:"openoffice.org-libs~1.1.2~44.2.0.EL3", rls:"CentOS3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org", rpm:"openoffice.org~1.1.5~10.6.0.7.EL4.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-base", rpm:"openoffice.org2-base~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-calc", rpm:"openoffice.org2-calc~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-core", rpm:"openoffice.org2-core~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-draw", rpm:"openoffice.org2-draw~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-emailmerge", rpm:"openoffice.org2-emailmerge~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-graphicfilter", rpm:"openoffice.org2-graphicfilter~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-impress", rpm:"openoffice.org2-impress~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-javafilter", rpm:"openoffice.org2-javafilter~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-af_ZA", rpm:"openoffice.org2-langpack-af_ZA~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-ar", rpm:"openoffice.org2-langpack-ar~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-bg_BG", rpm:"openoffice.org2-langpack-bg_BG~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-bn", rpm:"openoffice.org2-langpack-bn~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-ca_ES", rpm:"openoffice.org2-langpack-ca_ES~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-cs_CZ", rpm:"openoffice.org2-langpack-cs_CZ~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-cy_GB", rpm:"openoffice.org2-langpack-cy_GB~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-da_DK", rpm:"openoffice.org2-langpack-da_DK~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-de", rpm:"openoffice.org2-langpack-de~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-el_GR", rpm:"openoffice.org2-langpack-el_GR~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-es", rpm:"openoffice.org2-langpack-es~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-et_EE", rpm:"openoffice.org2-langpack-et_EE~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-eu_ES", rpm:"openoffice.org2-langpack-eu_ES~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-fi_FI", rpm:"openoffice.org2-langpack-fi_FI~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-fr", rpm:"openoffice.org2-langpack-fr~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-ga_IE", rpm:"openoffice.org2-langpack-ga_IE~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-gl_ES", rpm:"openoffice.org2-langpack-gl_ES~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-gu_IN", rpm:"openoffice.org2-langpack-gu_IN~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-he_IL", rpm:"openoffice.org2-langpack-he_IL~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-hi_IN", rpm:"openoffice.org2-langpack-hi_IN~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-hr_HR", rpm:"openoffice.org2-langpack-hr_HR~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-hu_HU", rpm:"openoffice.org2-langpack-hu_HU~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-it", rpm:"openoffice.org2-langpack-it~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-ja_JP", rpm:"openoffice.org2-langpack-ja_JP~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-ko_KR", rpm:"openoffice.org2-langpack-ko_KR~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-lt_LT", rpm:"openoffice.org2-langpack-lt_LT~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-ms_MY", rpm:"openoffice.org2-langpack-ms_MY~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-nb_NO", rpm:"openoffice.org2-langpack-nb_NO~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-nl", rpm:"openoffice.org2-langpack-nl~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-nn_NO", rpm:"openoffice.org2-langpack-nn_NO~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-pa_IN", rpm:"openoffice.org2-langpack-pa_IN~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-pl_PL", rpm:"openoffice.org2-langpack-pl_PL~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-pt_BR", rpm:"openoffice.org2-langpack-pt_BR~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-pt_PT", rpm:"openoffice.org2-langpack-pt_PT~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-ru", rpm:"openoffice.org2-langpack-ru~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-sk_SK", rpm:"openoffice.org2-langpack-sk_SK~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-sl_SI", rpm:"openoffice.org2-langpack-sl_SI~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-sr_CS", rpm:"openoffice.org2-langpack-sr_CS~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-sv", rpm:"openoffice.org2-langpack-sv~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-ta_IN", rpm:"openoffice.org2-langpack-ta_IN~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-th_TH", rpm:"openoffice.org2-langpack-th_TH~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-tr_TR", rpm:"openoffice.org2-langpack-tr_TR~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-zh_CN", rpm:"openoffice.org2-langpack-zh_CN~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-zh_TW", rpm:"openoffice.org2-langpack-zh_TW~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-zu_ZA", rpm:"openoffice.org2-langpack-zu_ZA~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-math", rpm:"openoffice.org2-math~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-pyuno", rpm:"openoffice.org2-pyuno~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-testtools", rpm:"openoffice.org2-testtools~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-writer", rpm:"openoffice.org2-writer~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2-xsltfilter", rpm:"openoffice.org2-xsltfilter~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-i18n", rpm:"openoffice.org-i18n~1.1.5~10.6.0.7.EL4.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-kde", rpm:"openoffice.org-kde~1.1.5~10.6.0.7.EL4.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-libs", rpm:"openoffice.org-libs~1.1.5~10.6.0.7.EL4.1", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org2", rpm:"openoffice.org2~2.0.4~5.7.0.6.0.1", rls:"CentOS4")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
