# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818705");
  script_version("2024-10-10T07:25:31+0000");
  script_cve_id("CVE-2021-40323", "CVE-2021-40324", "CVE-2021-40325");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-12 20:25:00 +0000 (Tue, 12 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-02 01:23:10 +0000 (Sat, 02 Oct 2021)");
  script_name("Fedora: Security Advisory for cobbler (FEDORA-2021-3a640d3d4c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC35");

  script_xref(name:"Advisory-ID", value:"FEDORA-2021-3a640d3d4c");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/H2DR36LRJWVOM4K4MEMKDCZ24DESMBWY");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cobbler'
  package(s) announced via the FEDORA-2021-3a640d3d4c advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cobbler is a network install server.  Cobbler supports PXE, ISO
virtualized installs, and re-installing existing Linux machines.
The last two modes use a helper tool, &#39, koan&#39, , that integrates with
cobbler.  There is also a web interface &#39, cobbler-web&#39,.  Cobbler&#39, s
advanced features include importing distributions from DVDs and rsync
mirrors, kickstart templating, integrated yum mirroring, and built-in
DHCP/DNS Management.  Cobbler has a XML-RPC API for integration with
other applications.");

  script_tag(name:"affected", value:"'cobbler' package(s) on Fedora 35.");

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

if(release == "FC35") {

  if(!isnull(res = isrpmvuln(pkg:"cobbler", rpm:"cobbler~3.2.2~2.fc35", rls:"FC35"))) {
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