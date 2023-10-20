# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64814");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-09 02:15:49 +0200 (Wed, 09 Sep 2009)");
  script_cve_id("CVE-2009-0200", "CVE-2009-0201");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-9256 (openoffice.org)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"Update Information:

CVE-2009-0200/CVE-2009-0201: Harden .doctable insert/delete record import
handling.

ChangeLog:

  * Wed Sep  2 2009 Caol�n McNamara  - 1:3.0.1-15.6

  - Resolves: rhbz#520772 copy/paste cockup

  * Mon Aug 31 2009 Caol�n McNamara  - 1:3.0.1-15.5

  - Resolves: CVE-2009-0200/CVE-2009-0201

  - Resolves: rhbz#499474 soffice and .recently-used.xbel

  - Resolves: rhbz#504419  openoffice.org-3.1.0.ooo102566.sc.less.frenetic.progress.patch

  - Resolves: rhbz#506039 workspace.pdfextfix02.patch upsidedown images in pdf import

  - Resolves: rhbz#514683 add openoffice.org-3.1.1.ooo104329.dbaccess.primarykeys.patch

  - make the last three patches applicable

  - Resolves: rbhz#501141 Images and Frames disappear in sequential printing");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update openoffice.org' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-9256");
  script_tag(name:"summary", value:"The remote host is missing an update to openoffice.org
announced via advisory FEDORA-2009-9256.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=500993");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=502194");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"broffice.org-base", rpm:"broffice.org-base~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"broffice.org-brand", rpm:"broffice.org-brand~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"broffice.org-calc", rpm:"broffice.org-calc~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"broffice.org-draw", rpm:"broffice.org-draw~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"broffice.org-impress", rpm:"broffice.org-impress~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"broffice.org-math", rpm:"broffice.org-math~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"broffice.org-writer", rpm:"broffice.org-writer~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-base", rpm:"openoffice.org-base~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-base-core", rpm:"openoffice.org-base-core~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-brand", rpm:"openoffice.org-brand~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-bsh", rpm:"openoffice.org-bsh~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-calc", rpm:"openoffice.org-calc~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-calc-core", rpm:"openoffice.org-calc-core~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-core", rpm:"openoffice.org-core~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-devel", rpm:"openoffice.org-devel~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-draw", rpm:"openoffice.org-draw~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-draw-core", rpm:"openoffice.org-draw-core~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-emailmerge", rpm:"openoffice.org-emailmerge~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-graphicfilter", rpm:"openoffice.org-graphicfilter~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-headless", rpm:"openoffice.org-headless~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-impress", rpm:"openoffice.org-impress~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-impress-core", rpm:"openoffice.org-impress-core~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-javafilter", rpm:"openoffice.org-javafilter~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-af_ZA", rpm:"openoffice.org-langpack-af_ZA~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ar", rpm:"openoffice.org-langpack-ar~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-as_IN", rpm:"openoffice.org-langpack-as_IN~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-bg_BG", rpm:"openoffice.org-langpack-bg_BG~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-bn", rpm:"openoffice.org-langpack-bn~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ca_ES", rpm:"openoffice.org-langpack-ca_ES~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-cs_CZ", rpm:"openoffice.org-langpack-cs_CZ~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-cy_GB", rpm:"openoffice.org-langpack-cy_GB~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-da_DK", rpm:"openoffice.org-langpack-da_DK~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-de", rpm:"openoffice.org-langpack-de~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-dz", rpm:"openoffice.org-langpack-dz~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-el_GR", rpm:"openoffice.org-langpack-el_GR~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-en", rpm:"openoffice.org-langpack-en~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-es", rpm:"openoffice.org-langpack-es~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-et_EE", rpm:"openoffice.org-langpack-et_EE~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-eu_ES", rpm:"openoffice.org-langpack-eu_ES~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-fi_FI", rpm:"openoffice.org-langpack-fi_FI~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-fr", rpm:"openoffice.org-langpack-fr~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ga_IE", rpm:"openoffice.org-langpack-ga_IE~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-gl_ES", rpm:"openoffice.org-langpack-gl_ES~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-gu_IN", rpm:"openoffice.org-langpack-gu_IN~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-he_IL", rpm:"openoffice.org-langpack-he_IL~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-hi_IN", rpm:"openoffice.org-langpack-hi_IN~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-hr_HR", rpm:"openoffice.org-langpack-hr_HR~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-hu_HU", rpm:"openoffice.org-langpack-hu_HU~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-it", rpm:"openoffice.org-langpack-it~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ja_JP", rpm:"openoffice.org-langpack-ja_JP~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-kn_IN", rpm:"openoffice.org-langpack-kn_IN~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ko_KR", rpm:"openoffice.org-langpack-ko_KR~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-lt_LT", rpm:"openoffice.org-langpack-lt_LT~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ml_IN", rpm:"openoffice.org-langpack-ml_IN~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-mr_IN", rpm:"openoffice.org-langpack-mr_IN~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ms_MY", rpm:"openoffice.org-langpack-ms_MY~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-nb_NO", rpm:"openoffice.org-langpack-nb_NO~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-nl", rpm:"openoffice.org-langpack-nl~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-nn_NO", rpm:"openoffice.org-langpack-nn_NO~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-nr_ZA", rpm:"openoffice.org-langpack-nr_ZA~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-nso_ZA", rpm:"openoffice.org-langpack-nso_ZA~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-or_IN", rpm:"openoffice.org-langpack-or_IN~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-pa_IN", rpm:"openoffice.org-langpack-pa_IN~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-pl_PL", rpm:"openoffice.org-langpack-pl_PL~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-pt_BR", rpm:"openoffice.org-langpack-pt_BR~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-pt_PT", rpm:"openoffice.org-langpack-pt_PT~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ru", rpm:"openoffice.org-langpack-ru~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-sk_SK", rpm:"openoffice.org-langpack-sk_SK~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-sl_SI", rpm:"openoffice.org-langpack-sl_SI~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-sr", rpm:"openoffice.org-langpack-sr~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ss_ZA", rpm:"openoffice.org-langpack-ss_ZA~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-st_ZA", rpm:"openoffice.org-langpack-st_ZA~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-sv", rpm:"openoffice.org-langpack-sv~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ta_IN", rpm:"openoffice.org-langpack-ta_IN~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-te_IN", rpm:"openoffice.org-langpack-te_IN~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-th_TH", rpm:"openoffice.org-langpack-th_TH~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-tn_ZA", rpm:"openoffice.org-langpack-tn_ZA~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-tr_TR", rpm:"openoffice.org-langpack-tr_TR~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ts_ZA", rpm:"openoffice.org-langpack-ts_ZA~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-uk", rpm:"openoffice.org-langpack-uk~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ur", rpm:"openoffice.org-langpack-ur~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ve_ZA", rpm:"openoffice.org-langpack-ve_ZA~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-xh_ZA", rpm:"openoffice.org-langpack-xh_ZA~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-zh_CN", rpm:"openoffice.org-langpack-zh_CN~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-zh_TW", rpm:"openoffice.org-langpack-zh_TW~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-langpack-zu_ZA", rpm:"openoffice.org-langpack-zu_ZA~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-math", rpm:"openoffice.org-math~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-math-core", rpm:"openoffice.org-math-core~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-pdfimport", rpm:"openoffice.org-pdfimport~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-presentation-minimizer", rpm:"openoffice.org-presentation-minimizer~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-presenter-screen", rpm:"openoffice.org-presenter-screen~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-pyuno", rpm:"openoffice.org-pyuno~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-report-builder", rpm:"openoffice.org-report-builder~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-rhino", rpm:"openoffice.org-rhino~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-sdk", rpm:"openoffice.org-sdk~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-sdk-doc", rpm:"openoffice.org-sdk-doc~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-testtools", rpm:"openoffice.org-testtools~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-ure", rpm:"openoffice.org-ure~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-wiki-publisher", rpm:"openoffice.org-wiki-publisher~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-writer", rpm:"openoffice.org-writer~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-writer-core", rpm:"openoffice.org-writer-core~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-xsltfilter", rpm:"openoffice.org-xsltfilter~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-debuginfo", rpm:"openoffice.org-debuginfo~3.0.1~15.6.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
