# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63193");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-01-20 22:42:09 +0100 (Tue, 20 Jan 2009)");
  script_cve_id("CVE-2008-2237", "CVE-2008-2238");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mandrake Security Advisory MDVSA-2009:006 (openoffice.org)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.0|2008\.1)");
  script_tag(name:"insight", value:"Heap-based overflow on functions to manipulate WMF and EMF files
in OpenOffice.org documents enables remote attackers to execute
arbitrary code on documents holding certain crafted either WMF or
EMF files (CVE-2008-2237) (CVE-2008-2238).

This update provide the fix for these security issues and further
openoffice.org-voikko package has been updated as it depends on
openoffice.org packages.

Affected: 2008.0, 2008.1");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:006");
  script_tag(name:"summary", value:"The remote host is missing an update to openoffice.org
announced via advisory MDVSA-2009:006.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"openoffice.org", rpm:"openoffice.org~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-devel", rpm:"openoffice.org-devel~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-devel-doc", rpm:"openoffice.org-devel-doc~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-galleries", rpm:"openoffice.org-galleries~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-gnome", rpm:"openoffice.org-gnome~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-kde", rpm:"openoffice.org-kde~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-af", rpm:"openoffice.org-l10n-af~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ar", rpm:"openoffice.org-l10n-ar~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-bg", rpm:"openoffice.org-l10n-bg~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-br", rpm:"openoffice.org-l10n-br~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-bs", rpm:"openoffice.org-l10n-bs~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ca", rpm:"openoffice.org-l10n-ca~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-cs", rpm:"openoffice.org-l10n-cs~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-cy", rpm:"openoffice.org-l10n-cy~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-da", rpm:"openoffice.org-l10n-da~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-de", rpm:"openoffice.org-l10n-de~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-el", rpm:"openoffice.org-l10n-el~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-en_GB", rpm:"openoffice.org-l10n-en_GB~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-es", rpm:"openoffice.org-l10n-es~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-et", rpm:"openoffice.org-l10n-et~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-eu", rpm:"openoffice.org-l10n-eu~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-fi", rpm:"openoffice.org-l10n-fi~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-fr", rpm:"openoffice.org-l10n-fr~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-he", rpm:"openoffice.org-l10n-he~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-hi", rpm:"openoffice.org-l10n-hi~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-hu", rpm:"openoffice.org-l10n-hu~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-it", rpm:"openoffice.org-l10n-it~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ja", rpm:"openoffice.org-l10n-ja~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ko", rpm:"openoffice.org-l10n-ko~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-mk", rpm:"openoffice.org-l10n-mk~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-nb", rpm:"openoffice.org-l10n-nb~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-nl", rpm:"openoffice.org-l10n-nl~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-nn", rpm:"openoffice.org-l10n-nn~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-pl", rpm:"openoffice.org-l10n-pl~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-pt", rpm:"openoffice.org-l10n-pt~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-pt_BR", rpm:"openoffice.org-l10n-pt_BR~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ru", rpm:"openoffice.org-l10n-ru~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-sk", rpm:"openoffice.org-l10n-sk~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-sl", rpm:"openoffice.org-l10n-sl~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-sv", rpm:"openoffice.org-l10n-sv~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ta", rpm:"openoffice.org-l10n-ta~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-tr", rpm:"openoffice.org-l10n-tr~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-zh_CN", rpm:"openoffice.org-l10n-zh_CN~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-zh_TW", rpm:"openoffice.org-l10n-zh_TW~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-zu", rpm:"openoffice.org-l10n-zu~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-mono", rpm:"openoffice.org-mono~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-ooqstart", rpm:"openoffice.org-ooqstart~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64", rpm:"openoffice.org64~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-devel", rpm:"openoffice.org64-devel~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-devel-doc", rpm:"openoffice.org64-devel-doc~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-galleries", rpm:"openoffice.org64-galleries~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-gnome", rpm:"openoffice.org64-gnome~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-kde", rpm:"openoffice.org64-kde~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-af", rpm:"openoffice.org64-l10n-af~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-ar", rpm:"openoffice.org64-l10n-ar~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-bg", rpm:"openoffice.org64-l10n-bg~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-br", rpm:"openoffice.org64-l10n-br~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-bs", rpm:"openoffice.org64-l10n-bs~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-ca", rpm:"openoffice.org64-l10n-ca~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-cs", rpm:"openoffice.org64-l10n-cs~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-cy", rpm:"openoffice.org64-l10n-cy~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-da", rpm:"openoffice.org64-l10n-da~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-de", rpm:"openoffice.org64-l10n-de~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-el", rpm:"openoffice.org64-l10n-el~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-en_GB", rpm:"openoffice.org64-l10n-en_GB~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-es", rpm:"openoffice.org64-l10n-es~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-et", rpm:"openoffice.org64-l10n-et~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-eu", rpm:"openoffice.org64-l10n-eu~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-fi", rpm:"openoffice.org64-l10n-fi~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-fr", rpm:"openoffice.org64-l10n-fr~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-he", rpm:"openoffice.org64-l10n-he~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-hi", rpm:"openoffice.org64-l10n-hi~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-hu", rpm:"openoffice.org64-l10n-hu~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-it", rpm:"openoffice.org64-l10n-it~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-ja", rpm:"openoffice.org64-l10n-ja~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-ko", rpm:"openoffice.org64-l10n-ko~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-mk", rpm:"openoffice.org64-l10n-mk~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-nb", rpm:"openoffice.org64-l10n-nb~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-nl", rpm:"openoffice.org64-l10n-nl~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-nn", rpm:"openoffice.org64-l10n-nn~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-pl", rpm:"openoffice.org64-l10n-pl~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-pt", rpm:"openoffice.org64-l10n-pt~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-pt_BR", rpm:"openoffice.org64-l10n-pt_BR~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-ru", rpm:"openoffice.org64-l10n-ru~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-sk", rpm:"openoffice.org64-l10n-sk~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-sl", rpm:"openoffice.org64-l10n-sl~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-sv", rpm:"openoffice.org64-l10n-sv~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-ta", rpm:"openoffice.org64-l10n-ta~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-tr", rpm:"openoffice.org64-l10n-tr~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-zh_CN", rpm:"openoffice.org64-l10n-zh_CN~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-zh_TW", rpm:"openoffice.org64-l10n-zh_TW~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-zu", rpm:"openoffice.org64-l10n-zu~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-mono", rpm:"openoffice.org64-mono~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-ooqstart", rpm:"openoffice.org64-ooqstart~2.2.1~4.6mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org", rpm:"openoffice.org~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-base", rpm:"openoffice.org-base~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-calc", rpm:"openoffice.org-calc~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-common", rpm:"openoffice.org-common~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-core", rpm:"openoffice.org-core~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-devel", rpm:"openoffice.org-devel~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-devel-doc", rpm:"openoffice.org-devel-doc~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-draw", rpm:"openoffice.org-draw~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-dtd-officedocument1.0", rpm:"openoffice.org-dtd-officedocument1.0~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-filter-binfilter", rpm:"openoffice.org-filter-binfilter~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-gnome", rpm:"openoffice.org-gnome~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-af", rpm:"openoffice.org-help-af~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-ar", rpm:"openoffice.org-help-ar~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-bg", rpm:"openoffice.org-help-bg~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-br", rpm:"openoffice.org-help-br~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-bs", rpm:"openoffice.org-help-bs~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-ca", rpm:"openoffice.org-help-ca~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-cs", rpm:"openoffice.org-help-cs~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-cy", rpm:"openoffice.org-help-cy~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-da", rpm:"openoffice.org-help-da~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-de", rpm:"openoffice.org-help-de~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-el", rpm:"openoffice.org-help-el~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-en_GB", rpm:"openoffice.org-help-en_GB~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-es", rpm:"openoffice.org-help-es~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-et", rpm:"openoffice.org-help-et~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-eu", rpm:"openoffice.org-help-eu~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-fi", rpm:"openoffice.org-help-fi~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-fr", rpm:"openoffice.org-help-fr~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-he", rpm:"openoffice.org-help-he~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-hi", rpm:"openoffice.org-help-hi~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-hu", rpm:"openoffice.org-help-hu~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-it", rpm:"openoffice.org-help-it~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-ja", rpm:"openoffice.org-help-ja~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-ko", rpm:"openoffice.org-help-ko~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-mk", rpm:"openoffice.org-help-mk~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-nb", rpm:"openoffice.org-help-nb~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-nl", rpm:"openoffice.org-help-nl~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-nn", rpm:"openoffice.org-help-nn~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-pl", rpm:"openoffice.org-help-pl~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-pt", rpm:"openoffice.org-help-pt~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-pt_BR", rpm:"openoffice.org-help-pt_BR~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-ru", rpm:"openoffice.org-help-ru~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-sk", rpm:"openoffice.org-help-sk~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-sl", rpm:"openoffice.org-help-sl~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-sv", rpm:"openoffice.org-help-sv~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-ta", rpm:"openoffice.org-help-ta~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-tr", rpm:"openoffice.org-help-tr~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-zh_CN", rpm:"openoffice.org-help-zh_CN~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-zh_TW", rpm:"openoffice.org-help-zh_TW~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-help-zu", rpm:"openoffice.org-help-zu~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-impress", rpm:"openoffice.org-impress~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-java-common", rpm:"openoffice.org-java-common~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-kde", rpm:"openoffice.org-kde~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-af", rpm:"openoffice.org-l10n-af~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ar", rpm:"openoffice.org-l10n-ar~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-bg", rpm:"openoffice.org-l10n-bg~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-br", rpm:"openoffice.org-l10n-br~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-bs", rpm:"openoffice.org-l10n-bs~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ca", rpm:"openoffice.org-l10n-ca~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-cs", rpm:"openoffice.org-l10n-cs~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-cy", rpm:"openoffice.org-l10n-cy~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-da", rpm:"openoffice.org-l10n-da~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-de", rpm:"openoffice.org-l10n-de~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-el", rpm:"openoffice.org-l10n-el~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-en_GB", rpm:"openoffice.org-l10n-en_GB~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-es", rpm:"openoffice.org-l10n-es~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-et", rpm:"openoffice.org-l10n-et~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-eu", rpm:"openoffice.org-l10n-eu~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-fi", rpm:"openoffice.org-l10n-fi~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-fr", rpm:"openoffice.org-l10n-fr~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-he", rpm:"openoffice.org-l10n-he~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-hi", rpm:"openoffice.org-l10n-hi~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-hu", rpm:"openoffice.org-l10n-hu~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-it", rpm:"openoffice.org-l10n-it~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ja", rpm:"openoffice.org-l10n-ja~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ko", rpm:"openoffice.org-l10n-ko~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-mk", rpm:"openoffice.org-l10n-mk~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-nb", rpm:"openoffice.org-l10n-nb~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-nl", rpm:"openoffice.org-l10n-nl~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-nn", rpm:"openoffice.org-l10n-nn~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-pl", rpm:"openoffice.org-l10n-pl~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-pt", rpm:"openoffice.org-l10n-pt~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-pt_BR", rpm:"openoffice.org-l10n-pt_BR~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ru", rpm:"openoffice.org-l10n-ru~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-sk", rpm:"openoffice.org-l10n-sk~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-sl", rpm:"openoffice.org-l10n-sl~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-sv", rpm:"openoffice.org-l10n-sv~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ta", rpm:"openoffice.org-l10n-ta~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-tr", rpm:"openoffice.org-l10n-tr~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-zh_CN", rpm:"openoffice.org-l10n-zh_CN~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-zh_TW", rpm:"openoffice.org-l10n-zh_TW~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-l10n-zu", rpm:"openoffice.org-l10n-zu~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-math", rpm:"openoffice.org-math~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-mono", rpm:"openoffice.org-mono~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-openclipart", rpm:"openoffice.org-openclipart~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-pyuno", rpm:"openoffice.org-pyuno~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-style-andromeda", rpm:"openoffice.org-style-andromeda~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-style-crystal", rpm:"openoffice.org-style-crystal~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-style-hicontrast", rpm:"openoffice.org-style-hicontrast~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-style-industrial", rpm:"openoffice.org-style-industrial~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-style-tango", rpm:"openoffice.org-style-tango~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-testtool", rpm:"openoffice.org-testtool~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org-writer", rpm:"openoffice.org-writer~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64", rpm:"openoffice.org64~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-base", rpm:"openoffice.org64-base~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-calc", rpm:"openoffice.org64-calc~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-common", rpm:"openoffice.org64-common~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-core", rpm:"openoffice.org64-core~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-devel", rpm:"openoffice.org64-devel~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-devel-doc", rpm:"openoffice.org64-devel-doc~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-draw", rpm:"openoffice.org64-draw~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-dtd-officedocument1.0", rpm:"openoffice.org64-dtd-officedocument1.0~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-filter-binfilter", rpm:"openoffice.org64-filter-binfilter~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-gnome", rpm:"openoffice.org64-gnome~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-af", rpm:"openoffice.org64-help-af~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-ar", rpm:"openoffice.org64-help-ar~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-bg", rpm:"openoffice.org64-help-bg~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-br", rpm:"openoffice.org64-help-br~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-bs", rpm:"openoffice.org64-help-bs~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-ca", rpm:"openoffice.org64-help-ca~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-cs", rpm:"openoffice.org64-help-cs~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-cy", rpm:"openoffice.org64-help-cy~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-da", rpm:"openoffice.org64-help-da~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-de", rpm:"openoffice.org64-help-de~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-el", rpm:"openoffice.org64-help-el~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-en_GB", rpm:"openoffice.org64-help-en_GB~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-es", rpm:"openoffice.org64-help-es~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-et", rpm:"openoffice.org64-help-et~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-eu", rpm:"openoffice.org64-help-eu~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-fi", rpm:"openoffice.org64-help-fi~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-fr", rpm:"openoffice.org64-help-fr~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-he", rpm:"openoffice.org64-help-he~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-hi", rpm:"openoffice.org64-help-hi~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-hu", rpm:"openoffice.org64-help-hu~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-it", rpm:"openoffice.org64-help-it~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-ja", rpm:"openoffice.org64-help-ja~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-ko", rpm:"openoffice.org64-help-ko~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-mk", rpm:"openoffice.org64-help-mk~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-nb", rpm:"openoffice.org64-help-nb~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-nl", rpm:"openoffice.org64-help-nl~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-nn", rpm:"openoffice.org64-help-nn~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-pl", rpm:"openoffice.org64-help-pl~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-pt", rpm:"openoffice.org64-help-pt~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-pt_BR", rpm:"openoffice.org64-help-pt_BR~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-ru", rpm:"openoffice.org64-help-ru~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-sk", rpm:"openoffice.org64-help-sk~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-sl", rpm:"openoffice.org64-help-sl~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-sv", rpm:"openoffice.org64-help-sv~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-ta", rpm:"openoffice.org64-help-ta~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-tr", rpm:"openoffice.org64-help-tr~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-zh_CN", rpm:"openoffice.org64-help-zh_CN~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-zh_TW", rpm:"openoffice.org64-help-zh_TW~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-help-zu", rpm:"openoffice.org64-help-zu~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-impress", rpm:"openoffice.org64-impress~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-java-common", rpm:"openoffice.org64-java-common~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-kde", rpm:"openoffice.org64-kde~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-af", rpm:"openoffice.org64-l10n-af~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-ar", rpm:"openoffice.org64-l10n-ar~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-bg", rpm:"openoffice.org64-l10n-bg~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-br", rpm:"openoffice.org64-l10n-br~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-bs", rpm:"openoffice.org64-l10n-bs~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-ca", rpm:"openoffice.org64-l10n-ca~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-cs", rpm:"openoffice.org64-l10n-cs~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-cy", rpm:"openoffice.org64-l10n-cy~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-da", rpm:"openoffice.org64-l10n-da~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-de", rpm:"openoffice.org64-l10n-de~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-el", rpm:"openoffice.org64-l10n-el~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-en_GB", rpm:"openoffice.org64-l10n-en_GB~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-es", rpm:"openoffice.org64-l10n-es~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-et", rpm:"openoffice.org64-l10n-et~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-eu", rpm:"openoffice.org64-l10n-eu~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-fi", rpm:"openoffice.org64-l10n-fi~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-fr", rpm:"openoffice.org64-l10n-fr~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-he", rpm:"openoffice.org64-l10n-he~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-hi", rpm:"openoffice.org64-l10n-hi~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-hu", rpm:"openoffice.org64-l10n-hu~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-it", rpm:"openoffice.org64-l10n-it~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-ja", rpm:"openoffice.org64-l10n-ja~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-ko", rpm:"openoffice.org64-l10n-ko~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-mk", rpm:"openoffice.org64-l10n-mk~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-nb", rpm:"openoffice.org64-l10n-nb~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-nl", rpm:"openoffice.org64-l10n-nl~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-nn", rpm:"openoffice.org64-l10n-nn~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-pl", rpm:"openoffice.org64-l10n-pl~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-pt", rpm:"openoffice.org64-l10n-pt~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-pt_BR", rpm:"openoffice.org64-l10n-pt_BR~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-ru", rpm:"openoffice.org64-l10n-ru~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-sk", rpm:"openoffice.org64-l10n-sk~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-sl", rpm:"openoffice.org64-l10n-sl~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-sv", rpm:"openoffice.org64-l10n-sv~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-ta", rpm:"openoffice.org64-l10n-ta~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-tr", rpm:"openoffice.org64-l10n-tr~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-zh_CN", rpm:"openoffice.org64-l10n-zh_CN~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-zh_TW", rpm:"openoffice.org64-l10n-zh_TW~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-l10n-zu", rpm:"openoffice.org64-l10n-zu~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-math", rpm:"openoffice.org64-math~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-mono", rpm:"openoffice.org64-mono~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-openclipart", rpm:"openoffice.org64-openclipart~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-pyuno", rpm:"openoffice.org64-pyuno~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-style-andromeda", rpm:"openoffice.org64-style-andromeda~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-style-crystal", rpm:"openoffice.org64-style-crystal~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-style-hicontrast", rpm:"openoffice.org64-style-hicontrast~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-style-industrial", rpm:"openoffice.org64-style-industrial~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-style-tango", rpm:"openoffice.org64-style-tango~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-testtool", rpm:"openoffice.org64-testtool~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openoffice.org64-writer", rpm:"openoffice.org64-writer~2.4.1.10~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
