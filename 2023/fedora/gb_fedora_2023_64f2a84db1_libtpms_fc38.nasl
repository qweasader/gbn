# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827349");
  script_version("2023-10-12T05:05:32+0000");
  script_cve_id("CVE-2023-1017", "CVE-2023-1018");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-10 02:04:00 +0000 (Fri, 10 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-16 02:03:09 +0000 (Thu, 16 Mar 2023)");
  script_name("Fedora: Security Advisory for libtpms (FEDORA-2023-64f2a84db1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-64f2a84db1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/I52XIAI5AN4EEF7VCTAXA6HRU6NX4S2P");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtpms'
  package(s) announced via the FEDORA-2023-64f2a84db1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A library providing TPM functionality for VMs. Targeted for integration
into Qemu.");

  script_tag(name:"affected", value:"'libtpms' package(s) on Fedora 38.");

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

if(release == "FC38") {

  if(!isnull(res = isrpmvuln(pkg:"libtpms", rpm:"libtpms~0.9.6~1.fc38", rls:"FC38"))) {
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
