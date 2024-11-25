# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856141");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2023-3758");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-13 01:01:04 +0000 (Mon, 13 May 2024)");
  script_name("openSUSE: Security Advisory for sssd (SUSE-SU-2024:1579-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1579-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3U5W73K3FCUY4T73YKQRFETZR5LSMBXI");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sssd'
  package(s) announced via the SUSE-SU-2024:1579-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for sssd fixes the following issues:

  * CVE-2023-3758: Fixed race condition during authorization that lead to GPO
      policies functioning inconsistently (bsc#1223100)

  ##");

  script_tag(name:"affected", value:"'sssd' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"libsss_certmap0-debuginfo", rpm:"libsss_certmap0-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-proxy-debuginfo", rpm:"sssd-proxy-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_nss_idmap0-debuginfo", rpm:"libsss_nss_idmap0-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-winbind-idmap-debuginfo", rpm:"sssd-winbind-idmap-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_idmap-devel", rpm:"libsss_idmap-devel~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-sss_nss_idmap", rpm:"python3-sss_nss_idmap~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-dbus-debuginfo", rpm:"sssd-dbus-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_certmap0", rpm:"libsss_certmap0~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_nss_idmap0", rpm:"libsss_nss_idmap0~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_idmap0-debuginfo", rpm:"libsss_idmap0-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac-devel", rpm:"libipa_hbac-devel~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_simpleifp-devel", rpm:"libsss_simpleifp-devel~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-common", rpm:"sssd-common~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ipa", rpm:"sssd-ipa~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ipa_hbac-debuginfo", rpm:"python3-ipa_hbac-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-debugsource", rpm:"sssd-debugsource~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnfsidmap-sss", rpm:"libnfsidmap-sss~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ad", rpm:"sssd-ad~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-sssd-config", rpm:"python3-sssd-config~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_certmap-devel", rpm:"libsss_certmap-devel~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-krb5-common", rpm:"sssd-krb5-common~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ad-debuginfo", rpm:"sssd-ad-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ipa_hbac", rpm:"python3-ipa_hbac~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-krb5", rpm:"sssd-krb5~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-krb5-debuginfo", rpm:"sssd-krb5-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-tools", rpm:"sssd-tools~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-krb5-common-debuginfo", rpm:"sssd-krb5-common-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-winbind-idmap", rpm:"sssd-winbind-idmap~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ipa-debuginfo", rpm:"sssd-ipa-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_nss_idmap-devel", rpm:"libsss_nss_idmap-devel~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-tools-debuginfo", rpm:"sssd-tools-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-sssd-config-debuginfo", rpm:"python3-sssd-config-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-kcm", rpm:"sssd-kcm~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ldap", rpm:"sssd-ldap~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_simpleifp0-debuginfo", rpm:"libsss_simpleifp0-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-dbus", rpm:"sssd-dbus~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-proxy", rpm:"sssd-proxy~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnfsidmap-sss-debuginfo", rpm:"libnfsidmap-sss-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd", rpm:"sssd~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-common-debuginfo", rpm:"sssd-common-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ldap-debuginfo", rpm:"sssd-ldap-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-kcm-debuginfo", rpm:"sssd-kcm-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-sss_nss_idmap-debuginfo", rpm:"python3-sss_nss_idmap-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_simpleifp0", rpm:"libsss_simpleifp0~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-sss-murmur", rpm:"python3-sss-murmur~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-sss-murmur-debuginfo", rpm:"python3-sss-murmur-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_idmap0", rpm:"libsss_idmap0~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac0", rpm:"libipa_hbac0~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac0-debuginfo", rpm:"libipa_hbac0-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-common-32bit", rpm:"sssd-common-32bit~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-common-32bit-debuginfo", rpm:"sssd-common-32bit-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-common-64bit-debuginfo", rpm:"sssd-common-64bit-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-common-64bit", rpm:"sssd-common-64bit~2.5.2~150500.10.17.1##", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_certmap0-debuginfo", rpm:"libsss_certmap0-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-proxy-debuginfo", rpm:"sssd-proxy-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_nss_idmap0-debuginfo", rpm:"libsss_nss_idmap0-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-winbind-idmap-debuginfo", rpm:"sssd-winbind-idmap-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_idmap-devel", rpm:"libsss_idmap-devel~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-sss_nss_idmap", rpm:"python3-sss_nss_idmap~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-dbus-debuginfo", rpm:"sssd-dbus-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_certmap0", rpm:"libsss_certmap0~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_nss_idmap0", rpm:"libsss_nss_idmap0~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_idmap0-debuginfo", rpm:"libsss_idmap0-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac-devel", rpm:"libipa_hbac-devel~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_simpleifp-devel", rpm:"libsss_simpleifp-devel~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-common", rpm:"sssd-common~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ipa", rpm:"sssd-ipa~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ipa_hbac-debuginfo", rpm:"python3-ipa_hbac-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-debugsource", rpm:"sssd-debugsource~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnfsidmap-sss", rpm:"libnfsidmap-sss~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ad", rpm:"sssd-ad~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-sssd-config", rpm:"python3-sssd-config~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_certmap-devel", rpm:"libsss_certmap-devel~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-krb5-common", rpm:"sssd-krb5-common~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ad-debuginfo", rpm:"sssd-ad-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ipa_hbac", rpm:"python3-ipa_hbac~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-krb5", rpm:"sssd-krb5~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-krb5-debuginfo", rpm:"sssd-krb5-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-tools", rpm:"sssd-tools~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-krb5-common-debuginfo", rpm:"sssd-krb5-common-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-winbind-idmap", rpm:"sssd-winbind-idmap~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ipa-debuginfo", rpm:"sssd-ipa-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_nss_idmap-devel", rpm:"libsss_nss_idmap-devel~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-tools-debuginfo", rpm:"sssd-tools-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-sssd-config-debuginfo", rpm:"python3-sssd-config-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-kcm", rpm:"sssd-kcm~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ldap", rpm:"sssd-ldap~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_simpleifp0-debuginfo", rpm:"libsss_simpleifp0-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-dbus", rpm:"sssd-dbus~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-proxy", rpm:"sssd-proxy~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnfsidmap-sss-debuginfo", rpm:"libnfsidmap-sss-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd", rpm:"sssd~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-common-debuginfo", rpm:"sssd-common-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ldap-debuginfo", rpm:"sssd-ldap-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-kcm-debuginfo", rpm:"sssd-kcm-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-sss_nss_idmap-debuginfo", rpm:"python3-sss_nss_idmap-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_simpleifp0", rpm:"libsss_simpleifp0~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-sss-murmur", rpm:"python3-sss-murmur~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-sss-murmur-debuginfo", rpm:"python3-sss-murmur-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_idmap0", rpm:"libsss_idmap0~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac0", rpm:"libipa_hbac0~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac0-debuginfo", rpm:"libipa_hbac0-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-common-32bit", rpm:"sssd-common-32bit~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-common-32bit-debuginfo", rpm:"sssd-common-32bit-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-common-64bit-debuginfo", rpm:"sssd-common-64bit-debuginfo~2.5.2~150500.10.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-common-64bit", rpm:"sssd-common-64bit~2.5.2~150500.10.17.1##", rls:"openSUSELeap15.5"))) {
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