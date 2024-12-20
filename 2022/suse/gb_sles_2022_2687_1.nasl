# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2687.1");
  script_tag(name:"creation_date", value:"2022-08-08 11:29:44 +0000 (Mon, 08 Aug 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2687-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2687-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222687-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fwupd' package(s) announced via the SUSE-SU-2022:2687-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for fwupd fixes the following issues:

Ignore non-PCI NVMe devices (e.g. NVMe-over-Fabrics) when probing
 (bsc#1193921)

package was rebuilt with new UEFI secure boot key. (bsc#1198581)");

  script_tag(name:"affected", value:"'fwupd' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"fwupd", rpm:"fwupd~1.7.3~150400.3.3.19", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupd-debuginfo", rpm:"fwupd-debuginfo~1.7.3~150400.3.3.19", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupd-debugsource", rpm:"fwupd-debugsource~1.7.3~150400.3.3.19", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupd-devel", rpm:"fwupd-devel~1.7.3~150400.3.3.19", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fwupd-lang", rpm:"fwupd-lang~1.7.3~150400.3.3.19", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfwupd2", rpm:"libfwupd2~1.7.3~150400.3.3.19", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfwupd2-debuginfo", rpm:"libfwupd2-debuginfo~1.7.3~150400.3.3.19", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfwupdplugin5", rpm:"libfwupdplugin5~1.7.3~150400.3.3.19", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfwupdplugin5-debuginfo", rpm:"libfwupdplugin5-debuginfo~1.7.3~150400.3.3.19", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Fwupd-2_0", rpm:"typelib-1_0-Fwupd-2_0~1.7.3~150400.3.3.19", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-FwupdPlugin-1_0", rpm:"typelib-1_0-FwupdPlugin-1_0~1.7.3~150400.3.3.19", rls:"SLES15.0SP4"))) {
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
