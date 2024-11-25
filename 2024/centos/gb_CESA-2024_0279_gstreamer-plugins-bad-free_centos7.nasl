# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884320");
  script_version("2024-04-11T05:05:26+0000");
  script_cve_id("CVE-2023-44446");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-04-11 05:05:26 +0000 (Thu, 11 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-03-05 14:32:57 +0000 (Tue, 05 Mar 2024)");
  script_name("CentOS: Security Advisory for gstreamer-plugins-bad-free (CESA-2024:0279)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2024:0279");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2024-January/099212.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer-plugins-bad-free'
  package(s) announced via the CESA-2024:0279 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GStreamer is a streaming media framework based on graphs of filters which operate on media data. The gstreamer-plugins-bad-free package contains a collection of plug-ins for GStreamer.

Security Fix(es):

  * gstreamer: MXF demuxer use-after-free vulnerability (CVE-2023-44446)

For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.");

  script_tag(name:"affected", value:"'gstreamer-plugins-bad-free' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-free", rpm:"gstreamer-plugins-bad-free~0.10.23~24.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-free-devel", rpm:"gstreamer-plugins-bad-free-devel~0.10.23~24.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-free-devel-docs", rpm:"gstreamer-plugins-bad-free-devel-docs~0.10.23~24.el7_9", rls:"CentOS7"))) {
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