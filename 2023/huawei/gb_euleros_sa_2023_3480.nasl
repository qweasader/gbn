# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.3480");
  script_cve_id("CVE-2023-4016");
  script_tag(name:"creation_date", value:"2023-12-22 04:20:17 +0000 (Fri, 22 Dec 2023)");
  script_version("2023-12-22T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-12-22 05:05:24 +0000 (Fri, 22 Dec 2023)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-15 18:19:00 +0000 (Fri, 15 Dec 2023)");

  script_name("Huawei EulerOS: Security Advisory for procps-ng (EulerOS-SA-2023-3480)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.10\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-3480");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3480");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'procps-ng' package(s) announced via the EulerOS-SA-2023-3480 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Under some circumstances, this weakness allows a user who has access to run the 'ps' utility on a machine, the ability to write almost unlimited amounts of unfiltered data into the process heap.(CVE-2023-4016)");

  script_tag(name:"affected", value:"'procps-ng' package(s) on Huawei EulerOS Virtualization release 2.10.0.");

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

if(release == "EULEROSVIRT-2.10.0") {

  if(!isnull(res = isrpmvuln(pkg:"procps-ng", rpm:"procps-ng~3.3.16~16.h9.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-ng-i18n", rpm:"procps-ng-i18n~3.3.16~16.h9.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
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
