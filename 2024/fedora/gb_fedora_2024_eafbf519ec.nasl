# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886825");
  script_cve_id("CVE-2024-2961");
  script_tag(name:"creation_date", value:"2024-05-27 10:48:40 +0000 (Mon, 27 May 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-eafbf519ec)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-eafbf519ec");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-eafbf519ec");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275855");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc' package(s) announced via the FEDORA-2024-eafbf519ec advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update includes several bug fixes from the upstream glibc release branch, including the fix for a buffer overflow in `iconv` when converting to the ISO-2022-CN-EXT character set (CVE-2024-2961, RHBZ#2275855).");

  script_tag(name:"affected", value:"'glibc' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"compat-libpthread-nonshared", rpm:"compat-libpthread-nonshared~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-all-langpacks", rpm:"glibc-all-langpacks~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-benchtests", rpm:"glibc-benchtests~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-benchtests-debuginfo", rpm:"glibc-benchtests-debuginfo~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-common-debuginfo", rpm:"glibc-common-debuginfo~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-debuginfo", rpm:"glibc-debuginfo~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-debugsource", rpm:"glibc-debugsource~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-doc", rpm:"glibc-doc~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-gconv-extra", rpm:"glibc-gconv-extra~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-gconv-extra-debuginfo", rpm:"glibc-gconv-extra-debuginfo~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-headers-s390", rpm:"glibc-headers-s390~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-headers-x86", rpm:"glibc-headers-x86~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-aa", rpm:"glibc-langpack-aa~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-af", rpm:"glibc-langpack-af~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-agr", rpm:"glibc-langpack-agr~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ak", rpm:"glibc-langpack-ak~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-am", rpm:"glibc-langpack-am~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-an", rpm:"glibc-langpack-an~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-anp", rpm:"glibc-langpack-anp~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ar", rpm:"glibc-langpack-ar~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-as", rpm:"glibc-langpack-as~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ast", rpm:"glibc-langpack-ast~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ayc", rpm:"glibc-langpack-ayc~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-az", rpm:"glibc-langpack-az~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-be", rpm:"glibc-langpack-be~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-bem", rpm:"glibc-langpack-bem~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ber", rpm:"glibc-langpack-ber~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-bg", rpm:"glibc-langpack-bg~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-bhb", rpm:"glibc-langpack-bhb~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-bho", rpm:"glibc-langpack-bho~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-bi", rpm:"glibc-langpack-bi~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-bn", rpm:"glibc-langpack-bn~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-bo", rpm:"glibc-langpack-bo~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-br", rpm:"glibc-langpack-br~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-brx", rpm:"glibc-langpack-brx~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-bs", rpm:"glibc-langpack-bs~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-byn", rpm:"glibc-langpack-byn~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ca", rpm:"glibc-langpack-ca~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ce", rpm:"glibc-langpack-ce~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-chr", rpm:"glibc-langpack-chr~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ckb", rpm:"glibc-langpack-ckb~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-cmn", rpm:"glibc-langpack-cmn~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-crh", rpm:"glibc-langpack-crh~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-cs", rpm:"glibc-langpack-cs~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-csb", rpm:"glibc-langpack-csb~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-cv", rpm:"glibc-langpack-cv~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-cy", rpm:"glibc-langpack-cy~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-da", rpm:"glibc-langpack-da~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-de", rpm:"glibc-langpack-de~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-doi", rpm:"glibc-langpack-doi~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-dsb", rpm:"glibc-langpack-dsb~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-dv", rpm:"glibc-langpack-dv~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-dz", rpm:"glibc-langpack-dz~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-el", rpm:"glibc-langpack-el~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-en", rpm:"glibc-langpack-en~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-eo", rpm:"glibc-langpack-eo~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-es", rpm:"glibc-langpack-es~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-et", rpm:"glibc-langpack-et~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-eu", rpm:"glibc-langpack-eu~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-fa", rpm:"glibc-langpack-fa~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ff", rpm:"glibc-langpack-ff~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-fi", rpm:"glibc-langpack-fi~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-fil", rpm:"glibc-langpack-fil~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-fo", rpm:"glibc-langpack-fo~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-fr", rpm:"glibc-langpack-fr~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-fur", rpm:"glibc-langpack-fur~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-fy", rpm:"glibc-langpack-fy~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ga", rpm:"glibc-langpack-ga~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-gbm", rpm:"glibc-langpack-gbm~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-gd", rpm:"glibc-langpack-gd~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-gez", rpm:"glibc-langpack-gez~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-gl", rpm:"glibc-langpack-gl~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-gu", rpm:"glibc-langpack-gu~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-gv", rpm:"glibc-langpack-gv~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ha", rpm:"glibc-langpack-ha~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-hak", rpm:"glibc-langpack-hak~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-he", rpm:"glibc-langpack-he~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-hi", rpm:"glibc-langpack-hi~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-hif", rpm:"glibc-langpack-hif~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-hne", rpm:"glibc-langpack-hne~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-hr", rpm:"glibc-langpack-hr~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-hsb", rpm:"glibc-langpack-hsb~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ht", rpm:"glibc-langpack-ht~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-hu", rpm:"glibc-langpack-hu~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-hy", rpm:"glibc-langpack-hy~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ia", rpm:"glibc-langpack-ia~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-id", rpm:"glibc-langpack-id~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ig", rpm:"glibc-langpack-ig~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ik", rpm:"glibc-langpack-ik~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-is", rpm:"glibc-langpack-is~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-it", rpm:"glibc-langpack-it~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-iu", rpm:"glibc-langpack-iu~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ja", rpm:"glibc-langpack-ja~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ka", rpm:"glibc-langpack-ka~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-kab", rpm:"glibc-langpack-kab~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-kk", rpm:"glibc-langpack-kk~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-kl", rpm:"glibc-langpack-kl~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-km", rpm:"glibc-langpack-km~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-kn", rpm:"glibc-langpack-kn~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ko", rpm:"glibc-langpack-ko~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-kok", rpm:"glibc-langpack-kok~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ks", rpm:"glibc-langpack-ks~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ku", rpm:"glibc-langpack-ku~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-kv", rpm:"glibc-langpack-kv~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-kw", rpm:"glibc-langpack-kw~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ky", rpm:"glibc-langpack-ky~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-lb", rpm:"glibc-langpack-lb~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-lg", rpm:"glibc-langpack-lg~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-li", rpm:"glibc-langpack-li~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-lij", rpm:"glibc-langpack-lij~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ln", rpm:"glibc-langpack-ln~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-lo", rpm:"glibc-langpack-lo~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-lt", rpm:"glibc-langpack-lt~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-lv", rpm:"glibc-langpack-lv~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-lzh", rpm:"glibc-langpack-lzh~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-mag", rpm:"glibc-langpack-mag~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-mai", rpm:"glibc-langpack-mai~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-mfe", rpm:"glibc-langpack-mfe~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-mg", rpm:"glibc-langpack-mg~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-mhr", rpm:"glibc-langpack-mhr~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-mi", rpm:"glibc-langpack-mi~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-miq", rpm:"glibc-langpack-miq~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-mjw", rpm:"glibc-langpack-mjw~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-mk", rpm:"glibc-langpack-mk~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ml", rpm:"glibc-langpack-ml~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-mn", rpm:"glibc-langpack-mn~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-mni", rpm:"glibc-langpack-mni~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-mnw", rpm:"glibc-langpack-mnw~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-mr", rpm:"glibc-langpack-mr~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ms", rpm:"glibc-langpack-ms~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-mt", rpm:"glibc-langpack-mt~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-my", rpm:"glibc-langpack-my~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-nan", rpm:"glibc-langpack-nan~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-nb", rpm:"glibc-langpack-nb~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-nds", rpm:"glibc-langpack-nds~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ne", rpm:"glibc-langpack-ne~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-nhn", rpm:"glibc-langpack-nhn~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-niu", rpm:"glibc-langpack-niu~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-nl", rpm:"glibc-langpack-nl~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-nn", rpm:"glibc-langpack-nn~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-nr", rpm:"glibc-langpack-nr~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-nso", rpm:"glibc-langpack-nso~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-oc", rpm:"glibc-langpack-oc~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-om", rpm:"glibc-langpack-om~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-or", rpm:"glibc-langpack-or~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-os", rpm:"glibc-langpack-os~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-pa", rpm:"glibc-langpack-pa~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-pap", rpm:"glibc-langpack-pap~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-pl", rpm:"glibc-langpack-pl~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ps", rpm:"glibc-langpack-ps~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-pt", rpm:"glibc-langpack-pt~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-quz", rpm:"glibc-langpack-quz~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-raj", rpm:"glibc-langpack-raj~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-rif", rpm:"glibc-langpack-rif~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ro", rpm:"glibc-langpack-ro~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ru", rpm:"glibc-langpack-ru~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-rw", rpm:"glibc-langpack-rw~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-sa", rpm:"glibc-langpack-sa~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-sah", rpm:"glibc-langpack-sah~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-sat", rpm:"glibc-langpack-sat~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-sc", rpm:"glibc-langpack-sc~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-sd", rpm:"glibc-langpack-sd~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-se", rpm:"glibc-langpack-se~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-sgs", rpm:"glibc-langpack-sgs~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-shn", rpm:"glibc-langpack-shn~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-shs", rpm:"glibc-langpack-shs~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-si", rpm:"glibc-langpack-si~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-sid", rpm:"glibc-langpack-sid~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-sk", rpm:"glibc-langpack-sk~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-sl", rpm:"glibc-langpack-sl~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-sm", rpm:"glibc-langpack-sm~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-so", rpm:"glibc-langpack-so~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-sq", rpm:"glibc-langpack-sq~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-sr", rpm:"glibc-langpack-sr~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ss", rpm:"glibc-langpack-ss~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ssy", rpm:"glibc-langpack-ssy~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-st", rpm:"glibc-langpack-st~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-su", rpm:"glibc-langpack-su~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-sv", rpm:"glibc-langpack-sv~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-sw", rpm:"glibc-langpack-sw~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-syr", rpm:"glibc-langpack-syr~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-szl", rpm:"glibc-langpack-szl~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ta", rpm:"glibc-langpack-ta~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-tcy", rpm:"glibc-langpack-tcy~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-te", rpm:"glibc-langpack-te~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-tg", rpm:"glibc-langpack-tg~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-th", rpm:"glibc-langpack-th~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-the", rpm:"glibc-langpack-the~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ti", rpm:"glibc-langpack-ti~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-tig", rpm:"glibc-langpack-tig~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-tk", rpm:"glibc-langpack-tk~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-tl", rpm:"glibc-langpack-tl~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-tn", rpm:"glibc-langpack-tn~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-to", rpm:"glibc-langpack-to~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-tok", rpm:"glibc-langpack-tok~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-tpi", rpm:"glibc-langpack-tpi~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-tr", rpm:"glibc-langpack-tr~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ts", rpm:"glibc-langpack-ts~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-tt", rpm:"glibc-langpack-tt~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ug", rpm:"glibc-langpack-ug~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-uk", rpm:"glibc-langpack-uk~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-unm", rpm:"glibc-langpack-unm~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ur", rpm:"glibc-langpack-ur~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-uz", rpm:"glibc-langpack-uz~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-ve", rpm:"glibc-langpack-ve~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-vi", rpm:"glibc-langpack-vi~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-wa", rpm:"glibc-langpack-wa~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-wae", rpm:"glibc-langpack-wae~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-wal", rpm:"glibc-langpack-wal~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-wo", rpm:"glibc-langpack-wo~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-xh", rpm:"glibc-langpack-xh~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-yi", rpm:"glibc-langpack-yi~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-yo", rpm:"glibc-langpack-yo~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-yue", rpm:"glibc-langpack-yue~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-yuw", rpm:"glibc-langpack-yuw~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-zgh", rpm:"glibc-langpack-zgh~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-zh", rpm:"glibc-langpack-zh~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-langpack-zu", rpm:"glibc-langpack-zu~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale-source", rpm:"glibc-locale-source~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-minimal-langpack", rpm:"glibc-minimal-langpack~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-nss-devel", rpm:"glibc-nss-devel~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-static", rpm:"glibc-static~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils-debuginfo", rpm:"glibc-utils-debuginfo~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc32", rpm:"glibc32~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc32-debuginfo", rpm:"glibc32-debuginfo~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnsl", rpm:"libnsl~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnsl-debuginfo", rpm:"libnsl-debuginfo~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss_db", rpm:"nss_db~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss_db-debuginfo", rpm:"nss_db-debuginfo~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss_hesiod", rpm:"nss_hesiod~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss_hesiod-debuginfo", rpm:"nss_hesiod-debuginfo~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sysroot-aarch64-fc40-glibc", rpm:"sysroot-aarch64-fc40-glibc~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sysroot-i386-fc40-glibc", rpm:"sysroot-i386-fc40-glibc~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sysroot-ppc64le-fc40-glibc", rpm:"sysroot-ppc64le-fc40-glibc~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sysroot-s390x-fc40-glibc", rpm:"sysroot-s390x-fc40-glibc~2.39~8.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sysroot-x86_64-fc40-glibc", rpm:"sysroot-x86_64-fc40-glibc~2.39~8.fc40", rls:"FC40"))) {
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
