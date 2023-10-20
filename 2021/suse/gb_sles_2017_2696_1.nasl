# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2696.1");
  script_cve_id("CVE-2016-8637");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:20:00 +0000 (Wed, 09 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2696-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2696-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172696-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dracut' package(s) announced via the SUSE-SU-2017:2696-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dracut fixes the following issues:
Security issues fixed:
- CVE-2016-8637: When the early microcode loading was enabled during
 initrd creation, the initrd would be read-only available for all users,
 allowing local users to retrieve secrets stored in the initial ramdisk.
 (bsc#1008340)
Non-security issues fixed:
- Skip iBFT discovery for qla4xxx flashnode session. (bsc#935320)
- Set MTU and LLADDR for DHCP if specified. (bsc#959803)
- Allow booting from degraded MD arrays with systemd. (bsc#1017695)
- Start multipath services before local-fs-pre.target. (bsc#1005410,
 bsc#1006118, bsc#1007925, bsc#986734, bsc#986838)
- Fixed /sbin/installkernel to handle kernel packages built with 'make
 bin-rpmpkg'. (bsc#1008648)
- Fixed typo in installkernel script. (bsc#1032576)
- Fixed subnet calculation in mkinitrd. (bsc#1035743)");

  script_tag(name:"affected", value:"'dracut' package(s) on SUSE Linux Enterprise Server 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"dracut", rpm:"dracut~037~51.31.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dracut-debuginfo", rpm:"dracut-debuginfo~037~51.31.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dracut-debugsource", rpm:"dracut-debugsource~037~51.31.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dracut-fips", rpm:"dracut-fips~037~51.31.1", rls:"SLES12.0"))) {
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
