# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2621.1");
  script_cve_id("CVE-2022-32742");
  script_tag(name:"creation_date", value:"2022-08-03 04:45:38 +0000 (Wed, 03 Aug 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-31 18:22:13 +0000 (Wed, 31 Aug 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2621-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2621-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222621-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the SUSE-SU-2022:2621-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for samba fixes the following issues:

CVE-2022-32742: Fixed incorrect length check in SMB1write,
 SMB1write_and_close, SMB1write_and_unlock (bso#15085) (bsc#1201496).");

  script_tag(name:"affected", value:"'samba' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Linux Enterprise High Availability 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-binding0-32bit", rpm:"libdcerpc-binding0-32bit~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-binding0-32bit-debuginfo", rpm:"libdcerpc-binding0-32bit-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-binding0", rpm:"libdcerpc-binding0~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-binding0-debuginfo", rpm:"libdcerpc-binding0-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-devel", rpm:"libdcerpc-devel~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-samr-devel", rpm:"libdcerpc-samr-devel~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-samr0", rpm:"libdcerpc-samr0~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-samr0-debuginfo", rpm:"libdcerpc-samr0-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc0-32bit", rpm:"libdcerpc0-32bit~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc0-32bit-debuginfo", rpm:"libdcerpc0-32bit-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc0", rpm:"libdcerpc0~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc0-debuginfo", rpm:"libdcerpc0-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-devel", rpm:"libndr-devel~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac-devel", rpm:"libndr-krb5pac-devel~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac0-32bit", rpm:"libndr-krb5pac0-32bit~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac0-32bit-debuginfo", rpm:"libndr-krb5pac0-32bit-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac0", rpm:"libndr-krb5pac0~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac0-debuginfo", rpm:"libndr-krb5pac0-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt-devel", rpm:"libndr-nbt-devel~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt0-32bit", rpm:"libndr-nbt0-32bit~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt0-32bit-debuginfo", rpm:"libndr-nbt0-32bit-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt0", rpm:"libndr-nbt0~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt0-debuginfo", rpm:"libndr-nbt0-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard-devel", rpm:"libndr-standard-devel~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard0-32bit", rpm:"libndr-standard0-32bit~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard0-32bit-debuginfo", rpm:"libndr-standard0-32bit-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard0", rpm:"libndr-standard0~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard0-debuginfo", rpm:"libndr-standard0-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr0-32bit", rpm:"libndr0-32bit~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr0-32bit-debuginfo", rpm:"libndr0-32bit-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr0", rpm:"libndr0~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr0-debuginfo", rpm:"libndr0-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi-devel", rpm:"libnetapi-devel~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0-32bit", rpm:"libnetapi0-32bit~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0-32bit-debuginfo", rpm:"libnetapi0-32bit-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0", rpm:"libnetapi0~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0-debuginfo", rpm:"libnetapi0-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials-devel", rpm:"libsamba-credentials-devel~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials0-32bit", rpm:"libsamba-credentials0-32bit~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials0-32bit-debuginfo", rpm:"libsamba-credentials0-32bit-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials0", rpm:"libsamba-credentials0~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials0-debuginfo", rpm:"libsamba-credentials0-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-errors-devel", rpm:"libsamba-errors-devel~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-errors0-32bit", rpm:"libsamba-errors0-32bit~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-errors0-32bit-debuginfo", rpm:"libsamba-errors0-32bit-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-errors0", rpm:"libsamba-errors0~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-errors0-debuginfo", rpm:"libsamba-errors0-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig-devel", rpm:"libsamba-hostconfig-devel~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig0-32bit", rpm:"libsamba-hostconfig0-32bit~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig0-32bit-debuginfo", rpm:"libsamba-hostconfig0-32bit-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig0", rpm:"libsamba-hostconfig0~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig0-debuginfo", rpm:"libsamba-hostconfig0-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-passdb-devel", rpm:"libsamba-passdb-devel~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-passdb0-32bit", rpm:"libsamba-passdb0-32bit~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-passdb0-32bit-debuginfo", rpm:"libsamba-passdb0-32bit-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-passdb0", rpm:"libsamba-passdb0~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-passdb0-debuginfo", rpm:"libsamba-passdb0-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy-devel", rpm:"libsamba-policy-devel~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy-python3-devel", rpm:"libsamba-policy-python3-devel~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0", rpm:"libsamba-policy0~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-debuginfo", rpm:"libsamba-policy0-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-python3", rpm:"libsamba-policy0-python3~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-python3-debuginfo", rpm:"libsamba-policy0-python3-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util-devel", rpm:"libsamba-util-devel~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util0-32bit", rpm:"libsamba-util0-32bit~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util0-32bit-debuginfo", rpm:"libsamba-util0-32bit-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util0", rpm:"libsamba-util0~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util0-debuginfo", rpm:"libsamba-util0-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb-devel", rpm:"libsamdb-devel~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb0-32bit", rpm:"libsamdb0-32bit~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb0-32bit-debuginfo", rpm:"libsamdb0-32bit-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb0", rpm:"libsamdb0~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb0-debuginfo", rpm:"libsamdb0-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient-devel", rpm:"libsmbclient-devel~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0-debuginfo", rpm:"libsmbclient0-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf-devel", rpm:"libsmbconf-devel~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf0-32bit", rpm:"libsmbconf0-32bit~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf0-32bit-debuginfo", rpm:"libsmbconf0-32bit-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf0", rpm:"libsmbconf0~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf0-debuginfo", rpm:"libsmbconf0-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap-devel", rpm:"libsmbldap-devel~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap2-32bit", rpm:"libsmbldap2-32bit~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap2-32bit-debuginfo", rpm:"libsmbldap2-32bit-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap2", rpm:"libsmbldap2~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap2-debuginfo", rpm:"libsmbldap2-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util-devel", rpm:"libtevent-util-devel~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util0-32bit", rpm:"libtevent-util0-32bit~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util0-32bit-debuginfo", rpm:"libtevent-util0-32bit-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util0", rpm:"libtevent-util0~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util0-debuginfo", rpm:"libtevent-util0-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient-devel", rpm:"libwbclient-devel~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0-32bit", rpm:"libwbclient0-32bit~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0-32bit-debuginfo", rpm:"libwbclient0-32bit-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0", rpm:"libwbclient0~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0-debuginfo", rpm:"libwbclient0-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ad-dc", rpm:"samba-ad-dc~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ad-dc-debuginfo", rpm:"samba-ad-dc-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-debuginfo", rpm:"samba-client-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-core-devel", rpm:"samba-core-devel~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debuginfo", rpm:"samba-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debugsource", rpm:"samba-debugsource~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-dsdb-modules", rpm:"samba-dsdb-modules~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-dsdb-modules-debuginfo", rpm:"samba-dsdb-modules-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-32bit", rpm:"samba-libs-32bit~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-32bit-debuginfo", rpm:"samba-libs-32bit-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs", rpm:"samba-libs~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-debuginfo", rpm:"samba-libs-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python", rpm:"samba-libs-python~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python-debuginfo", rpm:"samba-libs-python-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3", rpm:"samba-libs-python3~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3-debuginfo", rpm:"samba-libs-python3-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python", rpm:"samba-python~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python-debuginfo", rpm:"samba-python-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python3", rpm:"samba-python3~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python3-debuginfo", rpm:"samba-python3-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-32bit", rpm:"samba-winbind-32bit~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-32bit-debuginfo", rpm:"samba-winbind-32bit-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-debuginfo", rpm:"samba-winbind-debuginfo~4.9.5+git.490.e80cf669f50~150100.3.70.1", rls:"SLES15.0SP1"))) {
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
