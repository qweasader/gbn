# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871988");
  script_version("2023-06-21T05:06:23+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:23 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"creation_date", value:"2016-12-07 05:22:35 +0100 (Wed, 07 Dec 2016)");
  script_cve_id("CVE-2016-7155", "CVE-2016-7156", "CVE-2016-7170", "CVE-2016-7157",
                "CVE-2016-7466", "CVE-2016-7423", "CVE-2016-7422", "CVE-2016-7908",
                "CVE-2016-8576", "CVE-2016-7995");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 17:23:00 +0000 (Thu, 15 Oct 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for qemu FEDORA-2016-3d3218ec41");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"qemu on Fedora 25");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"FEDORA", value:"2016-3d3218ec41");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7ZUQQGMFOWMG7NODXLUESTHK53DSJV4S");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC25");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC25")
{

  if ((res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.7.0~4.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
