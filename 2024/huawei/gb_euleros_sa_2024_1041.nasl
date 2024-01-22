# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.1041");
  script_cve_id("CVE-2023-43785", "CVE-2023-43786", "CVE-2023-43787");
  script_tag(name:"creation_date", value:"2024-01-05 04:21:19 +0000 (Fri, 05 Jan 2024)");
  script_version("2024-01-05T16:09:35+0000");
  script_tag(name:"last_modification", value:"2024-01-05 16:09:35 +0000 (Fri, 05 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-13 13:18:00 +0000 (Fri, 13 Oct 2023)");

  script_name("Huawei EulerOS: Security Advisory for libX11 (EulerOS-SA-2024-1041)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.9\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-1041");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1041");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libX11' package(s) announced via the EulerOS-SA-2024-1041 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in libX11 due to an infinite loop within the PutSubImage() function. This flaw allows a local user to consume all available system resources and cause a denial of service condition.(CVE-2023-43786)

A vulnerability was found in libX11 due to a boundary condition within the _XkbReadKeySyms() function. This flaw allows a local user to trigger an out-of-bounds read error and read the contents of memory on the system.(CVE-2023-43785)

A vulnerability was found in libX11 due to an integer overflow within the XCreateImage() function. This flaw allows a local user to trigger an integer overflow and execute arbitrary code with elevated privileges.(CVE-2023-43787)");

  script_tag(name:"affected", value:"'libX11' package(s) on Huawei EulerOS Virtualization release 2.9.1.");

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

if(release == "EULEROSVIRT-2.9.1") {

  if(!isnull(res = isrpmvuln(pkg:"libX11", rpm:"libX11~1.6.9~4.h5.eulerosv2r9", rls:"EULEROSVIRT-2.9.1"))) {
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
