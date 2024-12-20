# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0087");
  script_cve_id("CVE-2019-5736");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-19 21:34:53 +0000 (Tue, 19 Feb 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0087)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0087");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0087.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24350");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2019/02/11/2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lxc' package(s) announced via the MGASA-2019-0087 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"LXC allows attackers to overwrite the host LXC binary (and consequently
obtain host root access) by leveraging the ability to execute a command as
root within one of these types of containers: a new container with an
attacker-controlled image, or an existing container, to which the attacker
previously had write access. This occurs because of file-descriptor
mishandling, related to /proc/self/exe. This attack is only possible with
privileged containers since it requires root privilege on the host to
overwrite the binary.");

  script_tag(name:"affected", value:"'lxc' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"lib64lxc-devel", rpm:"lib64lxc-devel~2.0.8~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64lxc1", rpm:"lib64lxc1~2.0.8~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblxc-devel", rpm:"liblxc-devel~2.0.8~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblxc1", rpm:"liblxc1~2.0.8~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua-lxc", rpm:"lua-lxc~2.0.8~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lxc", rpm:"lxc~2.0.8~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lxc-doc", rpm:"lxc-doc~2.0.8~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-lxc", rpm:"python3-lxc~2.0.8~1.1.mga6", rls:"MAGEIA6"))) {
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
