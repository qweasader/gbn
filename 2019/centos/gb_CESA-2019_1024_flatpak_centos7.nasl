# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883049");
  script_version("2023-05-10T09:37:12+0000");
  script_cve_id("CVE-2019-10063", "CVE-2017-5226");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-05-10 09:37:12 +0000 (Wed, 10 May 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-10 15:15:00 +0000 (Fri, 10 Jul 2020)");
  script_tag(name:"creation_date", value:"2019-05-14 02:00:35 +0000 (Tue, 14 May 2019)");
  script_name("CentOS Update for flatpak CESA-2019:1024 centos7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2019:1024");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-May/023300.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flatpak'
  package(s) announced via the CESA-2019:1024 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Flatpak is a system for building, distributing, and running sandboxed
desktop applications on Linux.

Security Fix(es):

  * flatpak: Sandbox bypass via IOCSTI (incomplete fix for CVE-2017-5226)
(CVE-2019-10063)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'flatpak' package(s) on CentOS 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"flatpak", rpm:"flatpak~1.0.2~5.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-builder", rpm:"flatpak-builder~1.0.0~5.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-devel", rpm:"flatpak-devel~1.0.2~5.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-libs", rpm:"flatpak-libs~1.0.2~5.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
