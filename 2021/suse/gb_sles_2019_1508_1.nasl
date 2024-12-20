# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1508.1");
  script_cve_id("CVE-2019-9928");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-25 16:58:30 +0000 (Thu, 25 Apr 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1508-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1508-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191508-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer-0_10-plugins-base' package(s) announced via the SUSE-SU-2019:1508-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gstreamer-0_10-plugins-base fixes the following issue:
Security issue fixed:
CVE-2019-9928: Fixed a heap-based overflow in the rtsp connection parser
 (bsc#1133375).");

  script_tag(name:"affected", value:"'gstreamer-0_10-plugins-base' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-0_10-plugins-base-32bit", rpm:"gstreamer-0_10-plugins-base-32bit~0.10.36~11.9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-0_10-plugins-base-debuginfo-32bit", rpm:"gstreamer-0_10-plugins-base-debuginfo-32bit~0.10.36~11.9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-0_10-0-32bit", rpm:"libgstapp-0_10-0-32bit~0.10.36~11.9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-0_10-0-debuginfo-32bit", rpm:"libgstapp-0_10-0-debuginfo-32bit~0.10.36~11.9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstinterfaces-0_10-0-32bit", rpm:"libgstinterfaces-0_10-0-32bit~0.10.36~11.9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstinterfaces-0_10-0-debuginfo-32bit", rpm:"libgstinterfaces-0_10-0-debuginfo-32bit~0.10.36~11.9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-0_10-plugins-base-32bit", rpm:"gstreamer-0_10-plugins-base-32bit~0.10.36~11.9.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-0_10-plugins-base-debuginfo-32bit", rpm:"gstreamer-0_10-plugins-base-debuginfo-32bit~0.10.36~11.9.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-0_10-0-32bit", rpm:"libgstapp-0_10-0-32bit~0.10.36~11.9.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-0_10-0-debuginfo-32bit", rpm:"libgstapp-0_10-0-debuginfo-32bit~0.10.36~11.9.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstinterfaces-0_10-0-32bit", rpm:"libgstinterfaces-0_10-0-32bit~0.10.36~11.9.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstinterfaces-0_10-0-debuginfo-32bit", rpm:"libgstinterfaces-0_10-0-debuginfo-32bit~0.10.36~11.9.1", rls:"SLES12.0SP1"))) {
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
