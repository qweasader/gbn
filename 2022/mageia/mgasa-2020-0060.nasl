# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0060");
  script_cve_id("CVE-2019-14904", "CVE-2019-14905");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-28 18:26:42 +0000 (Fri, 28 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0060)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0060");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0060.html");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2020:0217");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26125");
  script_xref(name:"URL", value:"https://github.com/ansible/ansible/blob/v2.7.16/changelogs/CHANGELOG-v2.7.rst");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ansible' package(s) announced via the MGASA-2020-0060 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the solaris_zone module from the Ansible Community
modules. When setting the name for the zone on the Solaris host, the
zone name is checked by listing the process with the 'ps' bare command
on the remote machine. An attacker could take advantage of this flaw by
crafting the name of the zone and executing arbitrary commands in the
remote host (CVE-2019-14904).

A vulnerability in Ansible's nxos_file_copy module can be used to copy
files to a flash or bootflash on NXOS devices. Malicious code could
craft the filename parameter to perform OS command injections. This
could result in a loss of confidentiality of the system among other
issues (CVE-2019-14905).");

  script_tag(name:"affected", value:"'ansible' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"ansible", rpm:"ansible~2.7.16~1.mga7", rls:"MAGEIA7"))) {
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
